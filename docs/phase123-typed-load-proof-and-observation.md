# Phase123：类型化 load 的证明与完整观察，以及入口与前提诊断

## 交付范围与剩余工作

实现以 Phase121 已验收代码为基础，继承 Phase122 整体修订方案。本轮完成 P1 的
普通 load 纵向能力包，以及 P0 的只读阶段化前提检查和入口身份选择基础。

已实现：

* 从 typed IR 的 LOAD 定义和 COPY/INT_SEXT/INT_ZEXT 链证明实际访问、扩展与最终
  GNU 输出载体；有限合同覆盖 8/16/32/64 位访问和可证明的符号/零扩展。
* Phase6A 候选、约束、Phase6D、渲染、L2 对象/值权威及 L3 调用共同消费该关系。
  独立访问宽度与载体宽度；32→64 零扩展明确使用 AMD64 32 位写清零高位的合同。
* L2 proof v4 仅为扩展 load 提供 sign_extend/zero_extend 权限；旧 v2/v3 不获得
  该权限，store 的既有 low_bits v3 保持。新增 load 对象范围/对齐检查仍全部执行。
* 单指针、单 load、编译器证明的无其它效应外壳，支持 signed/unsigned integer
  输出和返回，以及 const/non-const 整数指针。返回宽度至少容纳完整输出载体；
  对有信息损失的窄返回、void load、额外参数及一般外壳不新增许可。
* 输出到返回值的 C 转换单独建模。harness 用真实 typed backing object，通过实际
  调用观察返回值与完整对象字节；初始值包含零、最大正数、符号位、全一。
* 扩展 load 的 L2 harness 额外记录完整返回值，防止仅比较低位内存值漏掉错误高位；
  缺输出记录为 inconclusive，实际不相等为 failed。
* 新实验 v6、load deployment v3、load observation v4；拒绝版本降级。
  中央 provider/experiment 分派、部署重建、实际捕获解析和独立审计保持连接。
* 可选 memory backend v2 独立校准双端 read/write × 1/2/4/8 字节，共 16 个探针。
  旧 store wrapper v1 的 8 项校准继续保留，只能承担它已校准的域。
* 单入口路线按 compiler function identity 选择函数；无关函数不再仅因同处一个 TU
  被统一的函数数量检查拒绝。重复/错误身份仍拒绝，现有外壳和 exact-code 检查保留。
  此修改不是启用可达 callee、递归或一般调用图。
* `l3_capability_assessment` 是可选、只读的 recorded-static-prerequisites 检查器。
  分开源义务/权威、调用/外壳、声明机制和程序组合；所有运行阶段仍 not_run，
  semanticApproval 和 productionAcceptanceComplete 始终 false。声明 backend 名称
  不等于校准；旧调用尚未检查时明确 not_assessed，不判为已失效。

仍待实现：通用多参数/多输出调用、单片段多访问、混合机制联合执行、多对象/别名
闭包、fence/atomic 联合上下文、原子地址与 LRSC 活跃输出、更一般控制流/循环、
可达调用图和环境 L3。Phase122 方案仍是这些阶段的实施依据。联合拒绝 gate 保留，
不会通过忽略其它义务获得通过。

## 主要代码

`memory_access_semantics.py`、`memory_contracts.py`、`candidate_plans.py`、
`c_module/phase6c_x86_memory_inline_asm.py`、`phase6d_x86_memory_asm.py`、
`phase6f_contract_registry.py`、`l2_memory_object.py`、`automatic_l2_effect.py`、
`compiler_memory_signature.py`、`l3_memory_call.py`、`l3_trace_deployment.py`、
`l3_qemu_memory_route.py`、`l3_memory_backend.py`、`l3_entry_binding.py`、
`l3_capability_assessment.py`，以及 program/atomic 的入口选择和通用分派适配。

`test_typed_load_execution.py` 连接 IR、候选、证明、原生代码、L2 authority、typed
harness 和错误证据反例。`test_typed_load_backend.py` 编译真实 native 探针并测试
合成 callback transcript 的重放；这些 transcript 不是 QEMU 生产证据。
`test_l3_typed_load_production.py` 提供 18 项需显式环境启用的真实 L0–L3/独立审计
测试；每项在通过后篡改 raw capture，确认审计拒绝。

本地缺少 Clang、RISC-V GCC 和 QEMU，真实双端生产测试留待实验主机执行；
不能以收集测试、原生执行或校准完成替代生产验收。

## 本地验证记录

跨路线回归 1,719 项通过，无失败、错误或跳过；最后针对性检查 223 项通过，
包括随后补充的 signed-pointee 原生执行检查。18 项真实 load 生产测试已收集，
未在此执行。变更 Python 语法、git diff --check 和文档 shell 块语法检查通过。

## 1. 更新、构建与针对性检查

所有块使用 set +e，不关闭交互 shell。按阶段检查结果，失败时保留日志，
不要继续长矩阵，不覆盖旧目录。不要修改旧 manifest/hash 以绕过实现变更检查。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase123-typed-load-proof-and-observation
git switch --track origin/phase123-typed-load-proof-and-observation
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE123_ROOT="$(mktemp -d "$REPO/experiment/results/phase123-XXXXXX")"
hash -r
printf 'PHASE123_ROOT=%s\n' "$PHASE123_ROOT"
git rev-parse HEAD > "$PHASE123_ROOT/git-head.txt"
cmake --build build > "$PHASE123_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE123_ROOT/build.log"
```

构建成功后：

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_typed_load_execution.py \
  pytools/tests/test_typed_load_backend.py \
  pytools/tests/test_l3_entry_binding.py \
  pytools/tests/test_l3_capability_assessment.py \
  pytools/tests/test_l3_scalar_trace.py \
  pytools/tests/test_l3_scalar_call.py \
  pytools/tests/test_l3_typed_memory.py \
  pytools/tests/test_l3_memory_trace.py \
  --junitxml="$PHASE123_ROOT/focused.xml" \
  > "$PHASE123_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE123_ROOT/focused.log"
```

要求无 failure/error/skipped。它包括旧 scalar、store、memory 兼容检查，
不是只测试新 helper。

## 2. 重新准备包含读事件的 backend

必须使用 `--include-loads`，否则得到的仍是旧 store-only v1。

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --include-loads \
  --output "$PHASE123_ROOT/typed-memory-backend" \
  > "$PHASE123_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE123_ROOT/backend.log"
cat "$PHASE123_ROOT/typed-memory-backend/build-status.json"
```

要求返回 0、complete true、16 个探针完整。semanticApproval false 正确。
成功后：

```bash
export RV2X86_L3_TYPED_LOAD_BACKEND="$PHASE123_ROOT/typed-memory-backend/backend.json"
export RV2X86_L3_TYPED_MEMORY_BACKEND="$RV2X86_L3_TYPED_LOAD_BACKEND"
```

## 3. 先做一个符号扩展 load 的完整正例

```bash
mkdir -p "$PHASE123_ROOT/inputs"
cat > "$PHASE123_ROOT/inputs/typed-load-smoke.c" <<'C'
#include <stdint.h>
int64_t rv2x86_probe_signed_byte_load(const uint8_t *address) {
    int64_t output;
    __asm__ volatile("lb %[out],3(%[base])"
        : [out] "=r"(output) : [base] "r"(address) : "memory");
    return output;
}
C
python3 experiment/run_l3_memory_trace.py \
  --input "$PHASE123_ROOT/inputs/typed-load-smoke.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TYPED_LOAD_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$PHASE123_ROOT/load-smoke" \
  > "$PHASE123_ROOT/load-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'load_smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 80 "$PHASE123_ROOT/load-smoke.log"
```

要求返回 0。随后在未被反例修改的 smoke 目录独立审计：

```bash
python3 - <<'PY' > "$PHASE123_ROOT/load-smoke-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root=Path(os.environ['PHASE123_ROOT'])/'load-smoke'
state=json.loads((root/'run-status.json').read_text())
print('stage:',state.get('currentStage'),flush=True)
print('accepted:',state.get('productionAcceptanceComplete'),flush=True)
print('blockers:',state.get('blockers'),flush=True)
paths=list(root.glob('batch/cases/*/evaluation-result.json'))
if len(paths)!=1:raise ValueError('expected one evaluation report')
report=json.loads(paths[0].read_text())
print('evaluation:',report.get('status'),report.get('reasonCodes'),flush=True)
failures=[]
for attempt in report.get('attempts',[]):
    layers=(attempt.get('validation') or {}).get('layers',[])
    for layer in layers:
        print('LAYER:',layer.get('level'),layer.get('status'),flush=True)
        if layer.get('status')!='verified':print(layer.get('detail'),flush=True)
    if [(l.get('level'),l.get('status')) for l in layers]!=[(l,'verified') for l in ('L0','L1','L2','L3')]:
        failures.append('layers incomplete')
expected={'widthBytes':1,'byteOffset':3,'requiredAlignment':1,'carrierWidthBits':64,'valueProjection':'sign_extend'}
facts=[]
for path in root.rglob('translated_report.json'):
    for finding in json.loads(path.read_text()).get('findings',[]):
        value=(finding.get('approvalArtifact') or {}).get('l2MemoryProofFacts')
        print('MEMORY_FACTS:',value,flush=True);facts.append(value)
if len(facts)!=1 or not isinstance(facts[0],dict) or any(facts[0].get(k)!=v for k,v in expected.items()):
    failures.append('load facts mismatch')
if (state.get('currentStage')!='complete' or state.get('productionAcceptanceComplete') is not True
        or state.get('blockers') or report.get('status')!='verified' or not report.get('attempts')):
    failures.append('workflow incomplete')
if failures:raise ValueError(failures)
audit=audit_evaluation(report)
print('INDEPENDENT_AUDIT:',json.dumps(audit,ensure_ascii=False,indent=2),flush=True)
if audit.get('status')!='verified':raise ValueError('audit incomplete')
PY
AUDIT_STATUS=$?
printf 'load_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE123_ROOT/load-smoke-audit.log"
```

若失败，先读取 backend.stderr、pipeline/backend failure JSON、evaluation reasonCodes
和层 detail，不继续长矩阵。已校准的读事件只保证观察能力；不保证新的调用/证明
接口必然通过真实工具链。必须根据完整失败信息继续修订。

## 4. smoke 与独立审计成功后执行 18 项生产矩阵

```bash
export LOAD_MATRIX_ROOT="$(mktemp -d "$PHASE123_ROOT/load-matrix-XXXXXX")"
printf 'LOAD_MATRIX_ROOT=%s\n' "$LOAD_MATRIX_ROOT"
python3 -m pytest -vv -rs pytools/tests/test_l3_typed_load_production.py \
  --basetemp="$LOAD_MATRIX_ROOT/pytest" \
  --junitxml="$LOAD_MATRIX_ROOT/production.xml" \
  > "$LOAD_MATRIX_ROOT/production.log" 2>&1
MATRIX_STATUS=$?
printf 'load_matrix_status=%s\n' "$MATRIX_STATUS"
tail -n 140 "$LOAD_MATRIX_ROOT/production.log"
```

要求 18 passed，无失败/错误/跳过。包含符号/零扩展、signed/unsigned 输出、const
和 signed pointee，以及 32 位输出到 64 位返回的 C 转换。pytest 成功后会故意
篡改 capture 检验拒绝逻辑，因此不要把整个矩阵目录再次当全正例审计。

可随后使用同一个新 v2 backend 运行旧 store 生产矩阵作为兼容验收：

```bash
export STORE_MATRIX_ROOT="$(mktemp -d "$PHASE123_ROOT/store-compatibility-XXXXXX")"
python3 -m pytest -vv -rs pytools/tests/test_l3_typed_store_production.py \
  --basetemp="$STORE_MATRIX_ROOT/pytest" \
  --junitxml="$STORE_MATRIX_ROOT/production.xml" \
  > "$STORE_MATRIX_ROOT/production.log" 2>&1
STORE_STATUS=$?
printf 'store_compatibility_status=%s\n' "$STORE_STATUS"
tail -n 100 "$STORE_MATRIX_ROOT/production.log"
```

要求 17 passed。无需每个小修改后都重复这两个长矩阵。

## 5. 可选只读阶段化检查

```bash
python3 -m riscv2x86_py.l3_capability_assessment \
  --report "$PHASE123_ROOT/load-smoke/batch/cases/typed-load-smoke/work/translation-work/translated_report.json" \
  --capability memory \
  --output "$PHASE123_ROOT/load-prerequisites.json"
ASSESS_STATUS=$?
printf 'static_assessment_status=%s\n' "$ASSESS_STATUS"
```

此工具只检查保存的静态前提，返回 0 也不是执行验收；runtimeStages 仍 not_run。
返回 2 时阅读各 stage 的 unresolved/not_assessed 和 reasonCodes。
联合机制输入仍会指出 L3_JOINT_REGION_EXECUTION_CONTRACT_REQUIRED，不能因声明了
所有 backend 名称就通过。

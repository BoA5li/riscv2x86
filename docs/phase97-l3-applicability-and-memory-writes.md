# Phase97：L3 路线适用性、普通写入与表达式消费

基线：Phase96 `1ae58d6897fe3f0f003d1a5a4e4ce4723d02a48f`。

本轮修正已定位的生产/消费不一致，并扩展有界普通内存路线；不承诺 32 项全部获得 L3 verified。真实双 ISA 验收必须在安装工具链的实验主机上执行。本文的用例编号仅用于选择实验输入，生产实现按编译器事实、证明和适用域判断。

## 根因与实现

1. 普通读 producer 曾将所有已批准输入都送入 single-read 检查。一个不适用输入抛异常会阻断共享的需求产物发布。现在，四类明确的路线前提拒绝生成 response.v2、完整绑定的 disposition 和 **不完整 unknown** profile；L2/L3 需求仍分别分类。不得推导 intent=none，不得跳过必需 L3。真实 producer 错误、非法协议和身份变更仍拒绝；其 staging failure 明确归属 L3，并在驱动诊断中保留。终止于上游拒绝且没有获批产物的输入不伪造 profile。
2. 023/026 的 GNU `i` 约束字面量有编译器 AST，却没有声明 carrier。现在支持整数/字符字面量、括号和一元正负的有界 AST 求值，绑定原始表达式与类型，重放闭合；汇编物化输出实际常量，不分配虚构寄存器。复杂常量表达式、转换和指令立即数字段溢出不因此获得许可。**这修复编译器闭合与汇编输入，不等于已经补齐通用 L2 常量观察路线。**
3. 030 的 memory_lvalue 已被独立闭合，却被 provenance consumer 当成 integer carrier。现在重放 expression role/type/address/evaluation 绑定。存储 sidecar 的 aggregate/not_applicable 必须与实际 memory_lvalue 对应，不能按标量 signedness 比较。专用原子 authority 保留，未把不完整的通用 scalar boundary 改成 complete。原子操作仍不属于普通非原子内存 L3 路线。
4. 原普通读路线扩展到已证明的单次、非原子、64 位普通写入：明确可写域、指针参数 0、值参数 1；编译器 AST 证明函数仅有一次 asm，随后返回同一对象的绑定元素。外部 return 读取不纳入 asm 观察范围。新写入合同使用 experiment.v2，属性绑定必须是 approved-write；v1 不接受写入。两端都检查完整对象后状态和声明输入，不能仅比较相同返回值。仍独立重建并检查实际函数机器码、零字节标签、部署程序、原始事件及中央证据。

读取 v1 合同与原正向路线继续兼容。插件和 calibrated backend 未修改，无需为了本轮重建；每次消费仍核对其身份。

## 声称范围与剩余工作

支持的 L3 声称仍为 compiler-asm-region-only 的成功访存事件序列；可选模型为对象相对、空初始状态、LRU 的抽象片段流模型，对每次读/写触及的行更新驻留状态。它不表示真实写回/一致性协议、物理缓存、计时、推测或完整程序行为。

控制流、屏障、并发、原子、运行时同步、TIME 等需要各自的语义合同与观察机制。本次不会将这些输入报为普通内存路线成功，也不会把未证明的 L3 改为 not_applicable。016/022/024/029 的原环境组合验收继续作为兼容性实验，不能与当前独立 QEMU memory-trace 配置混用。未选环境时保持原上游拒绝。

## 1. 更新、环境和构建

在已激活的 .venv-l2 内逐块执行。所有 output 使用新目录；命令非零会保留 shell 和日志。构建非零时先查 build.log，不继续真实生产验收。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase97-l3-applicability-and-memory-writes
git switch --track origin/phase97-l3-applicability-and-memory-writes
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10="/usr/bin/clang-10"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE97_ROOT="$(mktemp -d "$REPO/experiment/results/phase97-XXXXXX")"
hash -r
printf 'PHASE97_ROOT=%s\n' "$PHASE97_ROOT"
command -v clang
clang --version
ls -l "$RV2X86_L3_TRACE_BACKEND"
cmake --build build -j2 > "$PHASE97_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE97_ROOT/build.log"
```

## 2. 定向回归与真实重命名生产验收

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_route_applicability.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_compiler_expression_evaluation.py \
  pytools/tests/test_atomic_expression_consumer.py \
  pytools/tests/test_l2_atomic_production.py \
  --junitxml="$PHASE97_ROOT/focused.xml" \
  > "$PHASE97_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 40 "$PHASE97_ROOT/focused.log"
```

定向测试通过后：

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE97_ROOT/production.xml" \
  > "$PHASE97_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE97_ROOT/production.log"
```

应为 **4 passed、0 skipped**：普通读/写各带模型与不带模型。每项要求 L0/L1/L2/L3、实际访存与中央审计成功，然后故意篡改临时轨迹要求审计拒绝。该临时目录因此不再是纯正向证据。主机若写入测试失败，保留实际失败阶段，不认定新路线已经真实验收。

## 3. 原始输入的独立正向验收

这组检查普通读写的不同偏移及原始命名。每项 output 不覆盖前次运行。

```bash
python3 -m riscv2x86_py.l3_cache_model \
  --output "$PHASE97_ROOT/cache-model.json" \
  --line-bytes 64 --set-count 16 --ways 4
MODEL_STATUS=$?
printf 'model_status=%s\n' "$MODEL_STATUS"
for SOURCE in \
  "$REPO"/experiment/generated-suite/case_000_*.c \
  "$REPO"/experiment/generated-suite/case_001_*.c \
  "$REPO"/experiment/generated-suite/case_004_*.c \
  "$REPO"/experiment/generated-suite/case_009_*.c
do
  CASE_NAME="$(basename "$SOURCE" .c)"
  python3 experiment/run_l3_memory_trace.py \
    --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_TRACE_BACKEND" \
    --cache-model "$PHASE97_ROOT/cache-model.json" \
    --output "$PHASE97_ROOT/original-$CASE_NAME" \
    > "$PHASE97_ROOT/original-$CASE_NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
done
```

每项必须生产退出 0、四层 verified、productionAcceptanceComplete=true、blockers=[]。写入事件应为 write，偏移和位宽匹配证明；模型属性应有独立结果。physicalMicroarchitectureClaimed 必须为 false。不能仅看 modelSelected=true 或工具退出码。

## 4. 32 项覆盖检查

前三步成功后才执行。这里检查覆盖边界和分类，**不期望 32 项全部退出 0**。每个输入独立生产，已支持案例不会被另一个不适用案例的全局非零掩盖。

```bash
for SOURCE in "$REPO"/experiment/generated-suite/*.c
do
  CASE_NAME="$(basename "$SOURCE" .c)"
  python3 experiment/run_l3_memory_trace.py \
    --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_TRACE_BACKEND" \
    --cache-model "$PHASE97_ROOT/cache-model.json" \
    --output "$PHASE97_ROOT/corpus-$CASE_NAME" \
    > "$PHASE97_ROOT/corpus-$CASE_NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
done
```

非内存输入应保留明确的 l3.intent.unsupported/前提不足及原始理由，而不是因为该 producer 不适用就丢失所有需求产物。若上游本身没有批准，仍保留 failed/unsupported/needs_route；不能要求这类输入执行后续层级。023/026 后续如停在 L2 常量观察，属于本文明确的剩余能力，不得据本轮闭合修复改报完整成功。

集中查看结果：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['PHASE97_ROOT'])
for path in sorted(root.glob('*/run-status.json')):
    data=json.loads(path.read_text())
    print('\nRUN:', path.parent.name)
    print('complete:', data.get('productionAcceptanceComplete'), 'stage:', data.get('currentStage'))
    print('blockers:', data.get('blockers'))
    for case in data.get('caseDiagnostics', []):
        print('CASE:', case['caseId'], case.get('status'), case.get('reasonCodes'))
        print('report:', case.get('reportPath'))
        print('staging:', case.get('requirementStagingFailure'))
        for attempt in case.get('attempts', []):
            print('translation:', attempt.get('translationOutcome'))
            print('layers:', [(x.get('level'),x.get('status')) for x in attempt.get('layers',[])])
PY
```

失败时再读取对应目录 batch.log、案例 evaluation-result.json 的全部 detail、翻译报告的 l3IntentDisposition、*.l3-requirements.json 与 *.requirement-failure.json。必须区分翻译未批准、L2 不完整、L3 机制不适用、部署失败与实际反例。

## 5. 兼容性及最终回归

恢复此前**真实且当前仍有效**的 controlled-system、local-sync 和 controlled-time backend/声明/runner 环境变量；不得填虚构值消除 skip。重跑此前 016/022/024/029 的独立及组合命令，输出改为本轮新目录；若工具身份已改变，重新准备，不能手改 identity。

verify_route_contracts 会把传入 clang 的目录放到 PATH 前。这里传入实际 Clang10 的 LLVM 目录，避免把 /usr/bin 中的 Clang6 置于最前。

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 /usr/lib/llvm-10/bin/clang \
  --output "$PHASE97_ROOT/regression-final" \
  --require-no-regression-skips \
  > "$PHASE97_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 35 "$PHASE97_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE97_ROOT/regression-final/run-status.json"
```

要求 failures/errors/skipped 全为 0。默认无 --suite，因此此步骤不冒充 32 项实验；32 项覆盖由前述独立生产执行记录。回归通过与特定支持域生产验收通过都必须分别报告。

## 开发环境验证

新增测试覆盖拒绝协议及重放、存储角色消费、literal 闭合/汇编物化、存储 AST scope、写入合同版本与属性绑定、原始对象后状态检查。真实 native GCC 写入 harness 已编译运行；它不能替代 RISC-V/QEMU 验收。开发容器缺少 llvm-mc/RISC-V GCC/QEMU，真实生产测试必须由主机执行。额外直接汇编测试因缺少 llvm-mc 失败，未改断言、未伪造工具；选定回归中的工具缺失按原规则报告 skip。

本轮开发验证：选定回归 1510 passed、47 skipped；最终定向集 52 passed。47 项跳过来自缺失的真实工具链及显式 backend 配置。额外两项直接汇编测试因 llvm-mc 不存在失败，属于未满足测试环境前提，主机仍须执行。

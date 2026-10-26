# Phase103：直接跳转保持、公共机制选择与纯标量多区域执行

基线为 Phase102 `7e700bf15133b82d7a9dc4e454adc1950f60321d`，其主机选定回归为 1724 项通过、零跳过。本轮落实推进方案 A/B：关闭直接跳转形态差异，建立公共机制执行计划，并提供 2–16 个纯标量汇编区域的整函数观察。**后续屏障、原子、指令可见性及受控环境 L3 路线尚未实现；本轮没有将这些义务删除或标为通过。**

## 变化与声明边界

- 原直接跳转 v1 只输出复制，本轮候选、6C、6D、翻译入口及渲染注册统一迁移至 `x86.gnu-att.local-unconditional-jump.direct-copy.u32-u64.v2`。目标实际执行一次直接跳转，再复制已证明的选中值；全部 GNU 输入、求值与 clobber 保留。旧批准身份不能自动授权新实现。控制比较标准保持不变，删除跳转的负向目标仍失败。
- `l3_execution_plan.py` 从完整权威义务选择机制；`l3_mechanism_selection.py` 提供显式校准后端映射，按证明事实选择普通内存、控制、纯标量整程序路线。能力选择不等于语义通过；当前不支持的跨机制同程序组合继续拒绝，环境互斥保护仍在。
- `compiler_program_regions.py` 从编译器 AST 导出直接复合语句中的全部区域和纯 C 外壳。`l3_program_spec.py` 重放所有标量 authority、片段边界、依赖图与程序执行 authority；遗漏任何成员均不能建立完整规格。
- 新插件 `runtime/l3_qemu_program_trace.c` 在**每端一次进程执行**中记录同一整函数全部区域的入口、出口与访存，保持原 C 中间数据流。每次函数调用中区域必须按顺序各完成一次。样本之间反复调用完整函数，不单独调用片段。
- C 语句标记仅用于定位。部署器把最终标签移入对应的原始 `#APP` 汇编代码，排除编译器的输入装载、输出回写和栈操作。对象及最终可执行文件的整个函数机器码必须与 L0 批准产物一致。GCC 合并相邻 APP 块也不能改变此要求。
- 新后端复用旧校准 QEMU，仅构建新插件并执行六项双端校准：两个区域无访存、第二个区域实际读取、跳过首区域的负向校准。旧 memory/control 后端实现和插件均保持不变。
- `l3_program_route.py` 共享一份实际双端捕获，逐成员归因及闭合。各成员引用同一 capture group 和执行身份；两个片段不计作两次独立程序样本。末值比较是附加检查，中间值语义仍依赖独立的 L2 证据，L3 不伪造中间值观察。
- 独立审核重新构建部署，复核加载映像、全体成员、收据、轨迹、命令、上下文、逐属性结果和汇总状态；同时支持有效反例。缺失成员、记录篡改、错误区域、失败状态被提升等均拒绝。

当前多区域域限于：单函数、2–16 个纯标量汇编片段、1–4 个 LP64 的 64 位整数参数及整数返回值、无环直接语句和无额外 C 副作用。当前不扩展为任意控制流、多函数或指针程序。所有结论限于声明区域及列出的样本；不声称缓存、周期、预测、推测执行或并发等价。

## 开发环境验证

相关 L3、批处理、配置、验证链、回归驱动及 L2 片段执行检查：527 passed、19 skipped。跳过的是未选择真实 QEMU 后端的生产测试，包括新增两项多区域生产测试，不是生产通过。

直接跳转/证明及新增区域检查另有 44 passed、2 skipped、1 deselected。被排除的是不属于本轮目标的既有 CSR 测试 `test_rv64_counter_csr_read_is_a_structured_runtime_route`：扩展运行该旧文件时，其 functional fallback 断言失败；在未修改的 Phase102 基线也复现同一失败（期待 functional_c，实际 needs_route）。本轮未修改该测试或放宽严格环境条件。该旧测试不在主机先前 1724 项选定回归清单中。

本地有实际原生 GCC 编译、UBSan 既有样本驱动、C 插件回调和整函数字节一致性测试；API 桩不替代真实双 ISA 生产执行。下面的主机步骤是本轮生产验收的必要部分。

## 1. 更新和构建

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase103-l3-jump-and-program-regions
git switch --track origin/phase103-l3-jump-and-program-regions
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10=/usr/lib/llvm-10/bin/clang
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export RV2X86_L3_CONTROL_BACKEND="$REPO/experiment/results/phase102-6NllZl/control-backend/backend.json"
export PHASE103_ROOT="$(mktemp -d "$REPO/experiment/results/phase103-XXXXXX")"
hash -r
printf 'PHASE103_ROOT=%s\n' "$PHASE103_ROOT"
git rev-parse HEAD > "$PHASE103_ROOT/git-head.txt"
cmake --build build > "$PHASE103_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE103_ROOT/build.log"
```

已有同名本地分支时直接 `git switch phase103-l3-jump-and-program-regions`，不要覆盖已有改动。核对交付提交及构建退出0，再继续。

## 2. 相关定向检查

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_control_spec.py \
  pytools/tests/test_l3_control_machine.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_phase6_rv64_add_contract.py::test_rv64_local_unconditional_jump_to_copy_is_proof_bound_and_renderable \
  --junitxml="$PHASE103_ROOT/focused.xml" \
  > "$PHASE103_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE103_ROOT/focused.log"
```

预期退出0，无错误、失败。本步骤含权威/成员遗漏、依赖篡改、实际插件回调、编译器栈访问边界、独立审核消费及直接跳转消除反例检查。

## 3. 真实控制生产验收及原始002

```bash
python3 -m pytest -vv -rs pytools/tests/test_l3_control_production.py \
  --junitxml="$PHASE103_ROOT/control-production.xml" \
  > "$PHASE103_ROOT/control-production.log" 2>&1
CONTROL_STATUS=$?
printf 'control_status=%s\n' "$CONTROL_STATUS"
tail -n 100 "$PHASE103_ROOT/control-production.log"

python3 experiment/run_l3_control_trace.py \
  --input "$REPO/experiment/generated-suite/case_002_7c7787fb86.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_CONTROL_BACKEND" \
  --output "$PHASE103_ROOT/original-jump" \
  > "$PHASE103_ROOT/original-jump.log" 2>&1
JUMP_STATUS=$?
printf 'jump_status=%s\n' "$JUMP_STATUS"
tail -n 70 "$PHASE103_ROOT/original-jump.log"
```

六项pytest仍应全部通过；**新版002驱动应退出0**，逻辑延续、实际转移形态、区域数据访问均verified，独立复核完成。Phase102中驱动退出1的旧反例应保留作历史证据，不改写旧报告。新版失败时先分析，不执行剩余耗时阶段。

## 4. 新增整程序观察器校准

```bash
python3 -m riscv2x86_py.l3_program_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE103_ROOT/program-backend" \
  > "$PHASE103_ROOT/program-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'program_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 90 "$PHASE103_ROOT/program-backend.log"
if [ -f "$PHASE103_ROOT/program-backend/build-status.json" ]; then
  cat "$PHASE103_ROOT/program-backend/build-status.json"
fi
```

预期退出0、complete=true、stage=complete。semanticApproval=false正确：校准只批准观察能力。没有backend.json时不要继续生产执行；提供本日志、build-status.json及失败校准的execute/build.command.json即可，无需重新构建QEMU。

## 5. 两/三区域真实变形验收和原始018

```bash
export RV2X86_L3_PROGRAM_BACKEND="$PHASE103_ROOT/program-backend/backend.json"
python3 -m pytest -vv -rs pytools/tests/test_l3_program_production.py \
  --junitxml="$PHASE103_ROOT/program-production.xml" \
  > "$PHASE103_ROOT/program-production.log" 2>&1
PROGRAM_STATUS=$?
printf 'program_production_status=%s\n' "$PROGRAM_STATUS"
tail -n 130 "$PHASE103_ROOT/program-production.log"
```

预期2 passed、0 skipped：重命名的两片段及三片段数据流，全部L0–L3通过；独立复核确认一份capture group；删除成员、修改原始区域轨迹被拒绝。

```bash
python3 experiment/run_l3_program_trace.py \
  --input "$REPO/experiment/generated-suite/case_018_e8928cf372.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_PROGRAM_BACKEND" \
  --output "$PHASE103_ROOT/original-program" \
  > "$PHASE103_ROOT/original-program.log" 2>&1
ORIGINAL_STATUS=$?
printf 'original_program_status=%s\n' "$ORIGINAL_STATUS"
tail -n 90 "$PHASE103_ROOT/original-program.log"
```

预期驱动0、executionComplete/independentResultAuditComplete/productionAcceptanceComplete均true，两个成员各自L0–L3 verified。captureGroupCount和programExecutionUnitCount为1，指一个双端整程序捕获组，不把两个片段当作两个独立程序样本；其中每端仍执行八组输入。

## 6. 公共机制选择的组合接入

创建显式后端选择，不使用文件名绑定机制：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ['PHASE103_ROOT'])
value = {'schemaVersion':'riscv2x86.l3-mechanism-selections.v1', 'backends':{
    'memory':os.environ['RV2X86_L3_TRACE_BACKEND'],
    'control':os.environ['RV2X86_L3_CONTROL_BACKEND'],
    'scalar-program':os.environ['RV2X86_L3_PROGRAM_BACKEND']}}
(root/'mechanisms.json').write_text(json.dumps(value, indent=2))
PY

for INDEX in 000 002 018
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 -m riscv2x86_py.automatic_batch_cli \
        --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
        --output-directory "$PHASE103_ROOT/selected-$CASE_NAME" \
        --jobs 1 --timeout-seconds 240 \
        --l3-mechanism-selections "$PHASE103_ROOT/mechanisms.json" \
        --require-l3 > "$PHASE103_ROOT/selected-$CASE_NAME.log" 2>&1
      SELECT_STATUS=$?
      printf '%s selected_status=%s\n' "$CASE_NAME" "$SELECT_STATUS"
    fi
  done
done
```

三项均应退出0，并生成productionAcceptanceComplete=true的l3-production-acceptance.json，分别验证内存、控制和多片段路线的自动选择。这里的INDEX仅用于选择实验输入；代码中的机制选择来自完整证明义务和能力。

## 7. 兼容和最终选定回归

前述门槛通过后，先运行原有内存/标量生产测试（预期11 passed、0 skipped），再沿用已审核system/time/local-sync等环境选择执行最终回归。本轮新测试已加入选定清单。

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  pytools/tests/test_l3_scalar_trace_production.py \
  --junitxml="$PHASE103_ROOT/compatibility.xml" \
  > "$PHASE103_ROOT/compatibility.log" 2>&1
COMPAT_STATUS=$?
printf 'compatibility_status=%s\n' "$COMPAT_STATUS"
tail -n 90 "$PHASE103_ROOT/compatibility.log"
```

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE103_ROOT/regression-final" \
  --require-no-regression-skips --regression-timeout-seconds 7200 \
  > "$PHASE103_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 40 "$PHASE103_ROOT/regression-driver.log"
if [ -f "$PHASE103_ROOT/regression-final/run-status.json" ]; then
  cat "$PHASE103_ROOT/regression-final/run-status.json"
fi
```

不要清空环境来规避失败或跳过；预期退出0、failures/errors/skipped均0。无需在每个小改动后重复全量回归。

## 后续明确未完成的工作

下一阶段仍须细分同步义务，修订普通fence源排序与目标加强关系的表达，再建立006和030专门观察/比较。018多区域成功也不能为原子、屏障或特权属性解除义务。016/022/024/029继续需要受控环境L3接入。新公共选择不接受未知跨机制组合，也不自动混用用户态和M-mode后端。

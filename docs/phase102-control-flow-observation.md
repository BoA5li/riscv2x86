# Phase102：编译器汇编区域的控制流 L3 观察

本轮增加独立的控制流观察后端、生产入口和结果复核。原有普通内存读写、标量区域观察及其判定标准保持不变。控制流路线不能与缓存模型或其它显式环境路线混选。

## 验证属性和范围

从编译器来源信息、L2 类型化证明、操作数边界和中央属性义务生成控制合同，不通过文件名、函数名或汇编文本决定可验证性。

控制流属性同时要求：

1. **逻辑延续一致**：实际执行的条件与输入绑定吻合，两端选择相同的延续；局部分支选择的返回值必须与对应输入一致。`asm goto` 还要求实际退出地址对应编译器绑定的 C 延续。
2. **实际转移形态一致**：比较实际执行路径中的条件转移和直接转移序列。不能仅凭最终返回值相等宣称此属性通过。
3. **区域数据访问一致**：此首版控制路线限定寄存器控制片段；两端区域内均应无数据访问。插件独立采集内存事件，出现实际数据访问将使相应属性失败。

观察来自 QEMU 每条实际执行指令的 PC 和区域退出事件。二进制解码建立有限 CFG，并用输入向量复核实际路径和条件。既不以静态可达性代替执行，也不以两端指令地址或机器码相等作为跨 ISA 标准。

当前有证据支持的通用域是：单函数、单汇编片段、1–4 个 LP64 的 64 位整数参数及整数返回值；局部无环单条件选择或直接跳转；以及编译器能导出唯一标签和两个独立延续的单参数 `asm goto`。参数有符号性由编译器类型导出，样本包含零、一、有符号边界和全一位模式，条件路线必须实际观察到两个结果。

未知编码、间接转移、调用、循环、无法绑定的值、32 位参数、歧义出口及其它机制义务均保留明确拒绝原因。样本结论限于列出的输入向量和所声明的片段区域。**不声称物理缓存、周期、分支预测、推测执行或整个测试集的微架构等价。** 原有同步、原子、时间及特权机制仍需各自的观察合同，本轮不将其降格为控制流属性。

## 代码和证据链

- `compiler_integer_signature.py`：编译器 AST 的 LP64 参数与返回类型事实。
- `l3_control_spec.py`、`l3_control_intent.py`：重放 L2 权限及证明，形成完整的属性义务、类型化条件、输入计划和生产意图收据。
- `l3_control_machine.py`：有界 RV64/RVC 与 AMD64 编码解码、参数和栈绑定、无环路径证人。未知语义拒绝；AMD64 标志位失效和重叠栈写入不会沿用旧事实。
- `runtime/l3_qemu_control_trace.c`、`l3_control_backend.py`：API-v1 插件与双 ISA 校准，记录入口、实际 PC、允许出口、内存访问和完成计数。校准含条件两侧、直接跳转、非法逃逸及数据访问，共十项。
- `l3_control_deployment.py`：对实际源/目标构建产物绑定观察区域。`asm goto` 延续从编译器位置插入零字节元数据标记，核对整个函数机器码不变，不能把独立汇编证明的局部偏移当作最终程序地址。
- `l3_control_route.py`：正常 L0/L1/L2 前提检查、双端执行、逐属性判定、中央闭合与独立重放。独立复核重新构建部署、核对加载映像、命令、原始轨迹和执行上下文，支持复核有效反例且不将失败提升为通过。
- `experiment/run_l3_control_trace.py`：正常批处理入口和独立复核驱动。退出码 0 为已复核通过；1 为完整执行并独立复核的属性反例；2 为前提/执行/复核未完成。始终查看 `run-status.json` 区分原因。

`case_002` 是关键负向验收：已有目标将源端直接跳转优化为单次复制。如新实验确认该事实，应得到逻辑延续通过、实际转移形态失败、区域数据访问通过。此时驱动应退出 1、`independentResultAuditComplete=true`，而 `productionAcceptanceComplete=false`。不要改写目标或放宽合同来把它变成 L3 通过。

## 本地检查与限制

开发环境验证包括真实原生 GCC 编码/函数字节检查、带 UBSan 的类型化样本驱动、插件 C 回调测试、路径/协议负向检查、属性闭合、现有 L3 与批处理兼容检查。API 桩测试不是双 QEMU 生产证据。本环境未配置用户的 RISC-V 工具链和校准后端，真实生产测试必须在下述环境完成。

本次相关回归结果：489 passed、17 skipped；跳过项为六项新增控制路线生产实验、四项原有内存生产实验和七项原有标量生产实验，均因未选择真实校准后端。新增控制测试及回归驱动的局部复核为 52 passed、6 skipped。没有将这些跳过计作生产通过。

## 主机验证步骤

所有命令保留非零状态，不执行 `exit`，不删除现有输出。失败时先保存当前日志，不自动继续到耗时的下一阶段。

### 1. 更新和准备

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase102-l3-control-flow-observation
git switch --track origin/phase102-l3-control-flow-observation
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10="/usr/lib/llvm-10/bin/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE102_ROOT="$(mktemp -d "$REPO/experiment/results/phase102-XXXXXX")"
hash -r
printf 'PHASE102_ROOT=%s\n' "$PHASE102_ROOT"
git rev-parse HEAD > "$PHASE102_ROOT/git-head.txt"
cmake --build build > "$PHASE102_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE102_ROOT/build.log"
```

若本地已经有该分支，用 `git switch phase102-l3-control-flow-observation`，不要覆盖工作区改动。先确认 HEAD 与交付提交相符、构建状态为 0，再继续。

### 2. 相关回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_control_machine.py \
  pytools/tests/test_l3_control_spec.py \
  pytools/tests/test_l3_control_backend.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_batch_evaluation_cli.py \
  --junitxml="$PHASE102_ROOT/focused.xml" \
  > "$PHASE102_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$PHASE102_ROOT/focused.log"
```

预期退出 0，无失败/错误。此步骤不代替真实双 ISA 控制流生产验证。

### 3. 准备控制观察器

复用已校准的 Phase95 QEMU 与工具链，只编译新增插件并运行十项新校准，不重新联网下载或构建 QEMU，也不改写原后端。

```bash
python3 -m riscv2x86_py.l3_control_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE102_ROOT/control-backend" \
  > "$PHASE102_ROOT/control-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'control_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 90 "$PHASE102_ROOT/control-backend.log"
if [ -f "$PHASE102_ROOT/control-backend/build-status.json" ]; then
  cat "$PHASE102_ROOT/control-backend/build-status.json"
fi
```

预期状态 0、`complete=true`、`stage=complete`；这只批准观察能力，不批准任意翻译语义。若未生成 `backend.json`，先提供本步骤日志和 `build-status.json`；不要启动下一个生产实验。

### 4. 变形输入生产验收

```bash
export RV2X86_L3_CONTROL_BACKEND="$PHASE102_ROOT/control-backend/backend.json"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_control_production.py \
  --junitxml="$PHASE102_ROOT/control-production.xml" \
  > "$PHASE102_ROOT/control-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'control_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 130 "$PHASE102_ROOT/control-production.log"
```

六项测试覆盖相等、不等、无符号和有符号比较、直接跳转反例及 `asm goto` 的两个延续。**预期 pytest 六项通过且无跳过**，其中直接跳转测试要求被测驱动正确返回反例（1），不是要求该翻译获得 L3 通过。测试还修改实际原始轨迹，确认独立复核拒绝被改写的证据。

### 5. 原始控制用例

只在前三项门槛通过后运行；保留所有返回码，不把 002 的反例混同于执行崩溃。

```bash
printf 'caseId\texitCode\n' > "$PHASE102_ROOT/control-exit-status.tsv"
for INDEX in 002 011 013 020 027
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 experiment/run_l3_control_trace.py \
        --input "$SOURCE" \
        --frontend "$RISCV2X86_TEST_FRONTEND" \
        --backend "$RV2X86_L3_CONTROL_BACKEND" \
        --output "$PHASE102_ROOT/$CASE_NAME" \
        > "$PHASE102_ROOT/$CASE_NAME.log" 2>&1
      CASE_STATUS=$?
      printf '%s\t%s\n' "$CASE_NAME" "$CASE_STATUS" >> "$PHASE102_ROOT/control-exit-status.tsv"
      printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
    fi
  done
done
```

汇总完整执行、独立复核和具体属性，不只看进程退出码：

```bash
python3 - <<'PY' > "$PHASE102_ROOT/control-summary.txt" 2>&1
import json, os
from pathlib import Path
root = Path(os.environ['PHASE102_ROOT'])
for path in sorted(root.glob('case_*/run-status.json')):
    data = json.loads(path.read_text())
    print('\nCASE:', path.parent.name)
    for key in ('currentStage', 'executionComplete', 'independentResultAuditComplete',
                'productionAcceptanceComplete', 'blockers'):
        print(key + ':', data.get(key))
    for item in data.get('acceptance', []):
        print('audit:', json.dumps(item, ensure_ascii=False))
    for item in data.get('caseDiagnostics', []):
        print('diagnostic:', json.dumps(item, ensure_ascii=False))
PY
cat "$PHASE102_ROOT/control-summary.txt"
```

002 的预期如上。其余四项预期完整执行、独立复核并通过；若出现 2 或独立复核未完成，应先定位该层日志，不提前宣称实现完成或重新跑整个测试集。

### 6. 兼容与最终回归

先运行原有内存和标量生产验收，确认新路线未破坏已验证机制：

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  pytools/tests/test_l3_scalar_trace_production.py \
  --junitxml="$PHASE102_ROOT/compatibility.xml" \
  > "$PHASE102_ROOT/compatibility.log" 2>&1
COMPAT_STATUS=$?
printf 'compatibility_status=%s\n' "$COMPAT_STATUS"
tail -n 100 "$PHASE102_ROOT/compatibility.log"
```

最后沿用已验证的受控 system、time、local-sync 等显式环境选择，不能清空变量来消除失败或跳过。选定回归已加入本轮四个测试文件：

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 "$CLANG10" \
  --output "$PHASE102_ROOT/regression-final" \
  --require-no-regression-skips \
  --regression-timeout-seconds 7200 \
  > "$PHASE102_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 40 "$PHASE102_ROOT/regression-driver.log"
if [ -f "$PHASE102_ROOT/regression-final/run-status.json" ]; then
  cat "$PHASE102_ROOT/regression-final/run-status.json"
fi
```

通过标准是构建和回归退出 0，`failures=errors=skipped=0`。测试通过证明所覆盖机制和反例处理，不代表其它尚无观察合同的同步/原子/特权属性已获得 L3 通过。后续覆盖扩展应继续逐机制新增义务、观察能力和负向验收，保留完整未覆盖清单。

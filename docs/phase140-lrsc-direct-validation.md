# Phase140：LR/SC 直接入口、完整操作计时与性能验证

基线：Phase139 `88583a19800281441581d312f0a3fa7b4ce9506d`。
分支：`phase140-lrsc-direct-validation`。

## 修订范围与原理

Phase138 实测 LR/SC 新进程审计约 64.50 秒。时间线确认主体约 32.99 秒，外层结束轮约 30.90 秒。
两次 receipt producer 重放分别约 21.68/21.93 秒；每个 producer 子进程又执行两轮完整后端来源验证。
主审计和两个 producer 共执行六次来源完整核验。AMO 使用直接 producer，每次约 0.93 秒。
51 项兼容矩阵中 27 项 LR/SC 共占约 75.45% 耗时。

本轮增加通用的显式单 LR/SC 后端入口，与既有直接 AMO 的分层方式一致：

- `automatic_batch_cli --l3-lrsc-backend` 在配置阶段验证真实后端，注册既有 LR/SC route。
- 使用已存在的 `l3_lrsc_intent` 外部进程；每轮仍真正运行 producer、核对 manifest、依赖、编译器事实、
  批准证明、结果 profile 和 receipt，不使用旧结果冒充重放。
- 执行、捕获、deployment 重建和独立审计继续由原有 route 验证后端、校准及来源。
  原有首次/结束轮复验、每次入口文件检查、审计隔离和反例拒绝均保留。
- `run_l3_lrsc_trace.py` 默认 `--entry-mode direct`；`--entry-mode selection` 保留完整通用选择路线。
  不是按测试名称、操作数位置或函数机器码选择捷径。
- 新增 runtime factory 只是连接既有 `l3_lrsc_route.build_route`，不另写宽松验证器。
  原子性/ordering/重试、对象范围、活跃输出、单片段等原有语义门槛没有扩大或删除。

producer 的纯语义重放不再附带重复通用选择器加载，不等于跳过后端验证，也不把父进程信任传给子进程。
通用选择路径依然可用并保留原来的严格检查。

`atomic.operation-complete.<name>` 覆盖整个操作，包括结束轮及其异常。
`inspect_validation_timing.py` 新增 `atomicOperations`，列出进程、操作名、完整耗时及同进程后代检查次数。
旧主体 span 保留。嵌套完整操作仍可能重叠，不能将所有 inclusive 时间相加作为 wall time。
旧日志缺少 complete span 时，不能将缺少记录理解为零开销。

性能比较报告升级为 `riscv2x86.atomic-performance-comparison.v2`：

| 参数 | condition 0 | condition 1 | 含义 |
| --- | --- | --- | --- |
| LR/SC `--lrsc-entry comparison` | selection + mode 0 | direct + mode 1 | 入口及复用策略的组合效果 |
| 上述参数再加 `--fixed-performance-mode 1` | selection + mode 1 | direct + mode 1 | 单独衡量本轮入口变化 |
| LR/SC `--lrsc-entry direct` | direct + mode 0 | direct + mode 1 | 固定新入口，单独衡量复用策略 |
| `--kind atomic` | mode 0 | mode 1 | 既有 AMO 复用策略回归 |

`condition` 是对照条件编号；`mode` 始终记录实际 RV2X86_ATOMIC_PERFORMANCE 值。
每次生产仍包含内部验收，另启动新进程独立审计；每轮重新核验输入摘要、完整 L0–L3、样本和真实输出。
没有缩减样本、校准集合、审计次数或负例。
基准对实参数量和对象指针归一化另加拒绝检查，防止 zip 截断或错误对象地址被归一化隐藏。

## 尚不作出的结论

本轮继承 Phase139 的六参数寄存器调用及 LR/SC SUB/SUBW。
它们仍须宿主真实验证。本轮没有完成全部 M4/M5：多输出、更广类型、非零偏移及原子对象别名、
全函数效应闭包、原子联合上下文、CFG 合流/多出口和有证明循环等缺口仍见 Phase139 说明。
不能用本轮性能优化或单路线生产通过宣称这些能力已完成。

剩余来源扫描仍完整执行。没有依据为省时取消 fsck、仅检查 mtime、跨独立审计持久化信任，
或用未经核验的 already_verified 标记授权。进一步消除来源扫描必须先证明相同信任窗口内确有重复。
本地缺少真实 RISC-V 编译器和校准 QEMU；当前不宣称真实双端验收成功或某个加速比。

## 本地验证记录

- 综合回归：1516 passed、24 skipped，133.38 秒。跳过项均为缺少真实 RISC-V 编译器的编译测试。
- 最终相关专项：151 passed，15.90 秒，与综合范围重叠，不累计计数；覆盖最后补充的固定模式入口对照和参数归一化反例。
- 完整真实生产矩阵已核对收集为 73 项（新增 10 + 既有 63）；本地没有真实双端运行结果。
- 11 个变更/新增 Python 文件通过 Python 3.10 AST 检查，13 个 Bash 块通过 bash -n；git diff --check 通过。
- 没有改动 source/target 语义证明、机器解释、LRSC route/backend、校准探针、原始观察与审计规则。
  对源/后端/轨迹的现有篡改测试仍在综合范围中执行。

## 1. 更新与环境

停止旧实验后再切换代码，保留旧目录。不要清理已有 build 修改。
本轮未修改 C++ 前端，无需仅为 Python 修订重新编译前端。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase140-lrsc-direct-validation
git switch --track origin/phase140-lrsc-direct-validation
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export RV2X86_ATOMIC_PERFORMANCE=1
unset RV2X86_VALIDATION_TIMING
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase140-XXXXXX")"
export TIMEFORMAT=$'wall_seconds=%R\nuser_seconds=%U\nsystem_seconds=%S'
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

同名分支已存在时，使用 `git switch phase140-lrsc-direct-validation`，再
`git merge --ff-only origin/phase140-lrsc-direct-validation`。

## 2. 快速功能与验证策略回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_lrsc_direct_entry.py \
  pytools/tests/test_atomic_call_contract.py \
  pytools/tests/test_lrsc_subtraction.py \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_lrsc_compiler_binding.py \
  pytools/tests/test_lrsc_source.py \
  pytools/tests/test_lrsc_live_return.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_lrsc_persistence.py \
  pytools/tests/test_l3_narrow_stack.py \
  pytools/tests/test_atomic_validation_operation.py \
  pytools/tests/test_atomic_performance_comparison.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_control_machine.py \
  pytools/tests/test_l3_control_spec.py \
  pytools/tests/test_l3_atomic_retry.py \
  pytools/tests/test_joint_provenance_performance.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_control_backend.py \
  pytools/tests/test_joint_operation_replay.py \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_joint_performance_comparison.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

要求无失败。宿主配置了真实交叉编译器后，24 项 RISC-V 编译测试应实际执行。
本地 native/authority fixture 通过不能代替双 ISA 执行。新入口专项还实际运行外部 producer，
但其中编译器/证明 fixture 不作为真实程序生产验收。

## 3. 重新准备版本绑定后端

复用底层 Phase95 QEMU；外层 wrapper 固定整个 Python 包，必须重建。不要编辑旧摘要。
每条命令退出码为 0、build-status 完整后，才进入下一条。

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_control_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/control-backend" > "$CHECK_ROOT/control-backend.log" 2>&1
CONTROL_STATUS=$?
printf 'control_backend_status=%s\n' "$CONTROL_STATUS"
tail -n 40 "$CHECK_ROOT/control-backend.log"
export RV2X86_L3_CONTROL_BACKEND="$CHECK_ROOT/control-backend/backend.json"
```

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$RV2X86_L3_CONTROL_BACKEND" \
  --output "$CHECK_ROOT/atomic-backend" > "$CHECK_ROOT/atomic-backend.log" 2>&1
ATOMIC_STATUS=$?
printf 'atomic_backend_status=%s\n' "$ATOMIC_STATUS"
tail -n 40 "$CHECK_ROOT/atomic-backend.log"
export RV2X86_L3_ATOMIC_BACKEND="$CHECK_ROOT/atomic-backend/backend.json"
```

```bash
python3 -m riscv2x86_py.l3_lrsc_backend \
  --control-backend "$RV2X86_L3_CONTROL_BACKEND" \
  --output "$CHECK_ROOT/lrsc-backend" > "$CHECK_ROOT/lrsc-backend.log" 2>&1
LRSC_STATUS=$?
printf 'lrsc_backend_status=%s\n' "$LRSC_STATUS"
tail -n 40 "$CHECK_ROOT/lrsc-backend.log"
export RV2X86_L3_LRSC_BACKEND="$CHECK_ROOT/lrsc-backend/backend.json"
```

校准仍分别为 control 10、AMO 138、LRSC 68。backend 的 semanticApproval=false 正常，不是程序验收。

## 4. 原失败输入：直接入口生产与新进程审计

```bash
RV2X86_VALIDATION_TIMING="$CHECK_ROOT/smoke-timing.jsonl" \
python3 experiment/run_l3_lrsc_trace.py \
  --input "$REPO/experiment/inputs/l3-lrsc-call-next.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_LRSC_BACKEND" \
  --entry-mode direct --output "$CHECK_ROOT/lrsc-smoke" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  > "$CHECK_ROOT/lrsc-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
cat "$CHECK_ROOT/lrsc-smoke/run-status.json"
```

要求 currentStage=complete，executionComplete、independentResultAuditComplete、productionAcceptanceComplete
均为 true，blockers=[]，entryMode=direct。然后新进程审计：

```bash
RV2X86_VALIDATION_TIMING="$CHECK_ROOT/smoke-audit-timing.jsonl" \
python3 -m riscv2x86_py.l3_production_acceptance \
  --evaluation "$CHECK_ROOT/lrsc-smoke/batch/cases/l3-lrsc-call-next/evaluation-result.json" \
  --output "$CHECK_ROOT/smoke-fresh-audit.json" > "$CHECK_ROOT/smoke-fresh-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'fresh_audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/smoke-fresh-audit.log"
```

要求退出码 0、独立验收 verified。不要将旧版本后端/报告用于新实现审计。
旧报告可只读分析，但它们固定了旧实现摘要。

## 5. 单独衡量本轮入口优化

两个条件均使用性能模式 1，仅改变 selection/direct。先 repeats=1 预检：

```bash
python3 experiment/run_atomic_performance_comparison.py \
  --kind lrsc --lrsc-entry comparison --fixed-performance-mode 1 \
  --input "$REPO/experiment/inputs/l3-lrsc-call-next.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_LRSC_BACKEND" \
  --output "$CHECK_ROOT/ab-entry-only" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --wall-timeout-seconds 7200 > "$CHECK_ROOT/ab-entry-only.log" 2>&1
ENTRY_STATUS=$?
printf 'entry_ab_status=%s\n' "$ENTRY_STATUS"
cat "$CHECK_ROOT/ab-entry-only/comparison.json"
```

要求 comparisonAxis=entry-only，两个 run 的 mode 都为 1，entryMode 分别为 selection/direct。
complete=true，各 run accepted=true，生产及 standaloneAudit 均 returnCode=0、未超时。
仅改变入口不能改变样本、参数、对象、返回值、必需性质或独立审计结论。

## 6. Phase139 新功能与全部性能策略的组合验证

六参数、32 位 SUBW、返回 next，包含真实生产及新进程独立审计：

```bash
python3 experiment/run_atomic_performance_comparison.py \
  --kind lrsc --lrsc-entry comparison \
  --input "$REPO/experiment/inputs/l3-lrsc-register-sub-next.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_LRSC_BACKEND" \
  --output "$CHECK_ROOT/ab-subtraction" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --wall-timeout-seconds 7200 > "$CHECK_ROOT/ab-subtraction.log" 2>&1
SUB_STATUS=$?
printf 'subtraction_ab_status=%s\n' "$SUB_STATUS"
cat "$CHECK_ROOT/ab-subtraction/comparison.json"
```

这里 comparisonAxis=entry-and-reuse，不能将加速比全部归因于单独入口优化。
若要单独衡量缓存策略，改用 --lrsc-entry direct，并指定一个新的输出目录。

AMO 固定入口回归：

```bash
python3 experiment/run_atomic_performance_comparison.py \
  --kind atomic --input "$REPO/experiment/inputs/l3-atomic-call-xor.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_ATOMIC_BACKEND" \
  --output "$CHECK_ROOT/ab-atomic" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --wall-timeout-seconds 7200 > "$CHECK_ROOT/ab-atomic.log" 2>&1
AMO_AB_STATUS=$?
printf 'atomic_ab_status=%s\n' "$AMO_AB_STATUS"
cat "$CHECK_ROOT/ab-atomic/comparison.json"
```

两组均要求完整验收，不缩减样本或审计。两个运行自己的原始地址/token 保留在证据中；
只在对照摘要中归一化，并先校验对象参数绑定；不强制两端重试次数相等。

## 7. 汇总完整操作及来源验证耗时

```bash
for MODE in selection direct
do
  DIR="$CHECK_ROOT/ab-entry-only/repeat-0-entry-$MODE-mode-1"
  for STAGE in production audit
  do
    python3 experiment/inspect_validation_timing.py \
      --input "$DIR/$STAGE-timing.jsonl" > "$DIR/$STAGE-timing-summary.json"
    SUMMARY_STATUS=$?
    printf '%s_%s_summary_status=%s\n' "$MODE" "$STAGE" "$SUMMARY_STATUS"
    cat "$DIR/$STAGE-timing-summary.json"
  done
done
```

重点看完整 standalone audit 对应的 atomicOperations，以及 intent、base-backend-full-validation、
provenance-full-validation、fsck 的调用数。直接 producer 不应再因机制选择器产生两轮后端验证。
实际执行和审计仍有必要的首次/结束核验。不要以某个固定总调用次数替代验收规则。
同进程 descendants 统计不包含子进程内部工作；进程汇总与外部 wall time 仍需分别解释。

## 8. 新增 M4 能力和选择入口兼容：10 项生产

```bash
{
  time python3 -m pytest -vv -rs --durations=0 \
    pytools/tests/test_l3_extended_call_production.py \
    pytools/tests/test_l3_lrsc_entry_production.py \
    -k 'register_boundary or subtraction_production or selected_lrsc_entry' \
    --basetemp="$CHECK_ROOT/new-pytest" \
    --junitxml="$CHECK_ROOT/new-production.xml" > "$CHECK_ROOT/new-production.log" 2>&1
} 2> "$CHECK_ROOT/new-production-resource.txt"
NEW_STATUS=$?
printf 'new_production_status=%s\n' "$NEW_STATUS"
tail -n 110 "$CHECK_ROOT/new-production.log"
cat "$CHECK_ROOT/new-production-resource.txt"
```

要求 10 passed、无 skipped：Phase139 新增 8 项，加 2 项通用选择入口兼容测试。
每项保留 L0–L3、独立审计、层状态和原始轨迹篡改拒绝检查。

## 9. 既有 63 项生产回归

```bash
{
  time python3 -m pytest -vv -rs --durations=0 \
    pytools/tests/test_l3_extended_call_production.py \
    pytools/tests/test_l3_atomic_production.py \
    pytools/tests/test_l3_lrsc_production.py \
    pytools/tests/test_l3_lrsc_live_production.py \
    pytools/tests/test_l3_control_production.py \
    -k 'not register_boundary and not subtraction_production' \
    --basetemp="$CHECK_ROOT/compat-pytest" \
    --junitxml="$CHECK_ROOT/compat-production.xml" > "$CHECK_ROOT/compat-production.log" 2>&1
} 2> "$CHECK_ROOT/compat-production-resource.txt"
COMPAT_STATUS=$?
printf 'compat_production_status=%s\n' "$COMPAT_STATUS"
tail -n 120 "$CHECK_ROOT/compat-production.log"
cat "$CHECK_ROOT/compat-production-resource.txt"
```

要求 63 passed、无 skipped，包含 18 项直接 AMO、既有 LR/SC old/next/status、控制及扩展调用回归。
生产测试最后故意破坏自己的证据来验证拒绝，不能再把这些目录用于未损坏的性能审计。
上面的 smoke/A-B 目录与这些负例目录相互独立。

## 10. 稳定性能结论与完成条件

功能和预检全部通过后，用新目录将第 5 步改为 repeats>=3，建议 4 次使两种顺序均衡；
保留机器负载、编译器、代码/后端/输入摘要和各次结果。不能仅凭一次测量作稳定加速比结论。

完成条件：快速回归无失败，真实编译不跳过；wrapper 完整；smoke、新进程审计及 A/B 全部验收；
10+63 项生产通过；实际完整 wall time 和来源验证数量支持性能改善。
若功能通过但性能未改善，性能目标仍未验收，应分析新的计时，不能删检查换取通过。
此完成条件覆盖 Phase139 已实现支持域及本轮性能修订，不代表 M4/M5 全阶段完成。

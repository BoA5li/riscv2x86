# Phase137：原子与 LR/SC 操作范围内的性能优化及验收

基线：Phase136 `42848ad05d93f4209809506fd40011c61bdc3349`。
分支：`phase137-atomic-validation-performance`。

本轮只优化已有支持域的执行成本，没有完成或扩大 M4/M5 的全部语义覆盖。
Phase136 的三/四参数原子调用与 control 唯一入口改动仍需要真实生产验收。

## 实施内容与安全边界

| 改动 | 保留的正确性条件 |
| --- | --- |
| 新增独立 atomic operation，评估及 atomic/LRSC 独立审计分别建作用域 | 无磁盘/跨进程缓存；PID、线程隔离；只复用成功的 JSON 原生结果；深拷贝；bool/int 类型敏感 |
| 基础 QEMU 来源核验共享 | 首次完整核验，成功返回前在新 epoch 完整核验；每次消费重新检查 manifest 与全部 files 内容摘要 |
| 等价来源核验算法接入 | 使用 Phase134 已建立 AST 门槛等价性与真实 Git 篡改回归的 companion；继续检查全部文件、Git 对象、HEAD/tree、模式、符号链接与工作树。未改原有三个 pinned QEMU 文件 |
| control、AMO、LRSC 校准解析共享 | 每个校准的 binary、assembly、raw trace、execute/build command 在每次消费重新计算摘要；首次与结束轮均解析全部校准，不减少记录与失败路径 |
| atomic/LRSC-only mechanism selection 作用域与共享 | 保留外部进度回调、选择身份、全 backend/schema/tool/file/coverage 检查与结束核验；其它机制选择规则不变 |
| 原子意图生产重放共享 | 仅已识别的 compiler-atomic-region/compiler-lrsc-region；源、报告、编译器快照、attempt archive、manifest 均进入键并检查；结束轮再次调用原生产者，逐成员 receipt/profile 比较保留 |
| 损坏证据提前拒绝 | contract/选择身份检查后，昂贵后端/部署重建前先核对原始轨迹和命令摘要；后续原位置检查与完整解析仍保留 |
| 细分计时与同版本 A/B | 独立开关 `RV2X86_ATOMIC_PERFORMANCE=0/1`；0 运行原完整工作路径，1 使用新策略；相同输入、代码、后端、样本计划和验收条件 |

结束核验不能使用初始 epoch 的结果。初始阶段出现但结束根遍历未消费的叶节点仍逐一重放。
结束核验失败会抛出异常，调用者不能收到成功结果。嵌套独立审计从空状态开始，返回后恢复外层作用域。

校准共享仅用于这三个固定检查器实际消费的 command-selection context。
后端自身的 schema、全部实现文件集合、身份、工具一致性、完整校准 case 集合仍在每次 validate 中核查。
原始生产轨迹的解析、实际执行、完整结果对象、机器归因、ordering、重试依据、部署重建和样本集合没有缓存替代。

本轮没有给单次独立部署重建增加缓存：当前每次审计需要它建立独立依据，强行增加首次与结束两次重建可能更慢。
没有缓存 ELF 全局对象或仅凭 mtime/大小信任文件；没有跨测试共享审计结论，也没有并行争用 QEMU 校准目录。
这几项应由新计时确认重复工作后再优化，不能把删除必要工作当作优化。

## 本地验证记录

- 综合相关回归：1059 passed，127.31 秒。
- 最终新增专项：44 passed，2.79 秒；与综合范围重叠，不相加。
- 63 项真实生产因未选择校准后端而 skipped，不能算通过。
- 15 个变更 Python 文件通过 Python 3.10 AST 检查；git diff --check 通过。
- 真实双 ISA 验收与加速倍数尚未测量。

## 1. 更新与环境

先结束正在运行的旧版本实验，保留其目录。运行中切换实现会正确触发摘要拒绝。
Bash 下激活 `.venv-l2` 后执行：

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase137-atomic-validation-performance
git switch --track origin/phase137-atomic-validation-performance
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_ATOMIC_PERFORMANCE=1
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase137-XXXXXX")"
export TIMEFORMAT=$'wall_seconds=%R\nuser_seconds=%U\nsystem_seconds=%S'
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

同名本地分支已存在时，改用 `git switch phase137-atomic-validation-performance`，随后
`git merge --ff-only origin/phase137-atomic-validation-performance`。
不清理已有 build 修改。本轮未修改 C++ 前端，无需为 Python 性能变化重新编译前端。
本指南使用 Bash `time`，不依赖缺失的 `/usr/bin/time`。

## 2. 快速正确性回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_atomic_validation_operation.py \
  pytools/tests/test_atomic_performance_comparison.py \
  pytools/tests/test_atomic_call_contract.py \
  pytools/tests/test_lrsc_live_return.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_lrsc_persistence.py \
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
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

要求退出码 0、无失败，检查 skipped 的具体原因，不能把 skipped 当通过。
新增测试包含 138 个 AMO 校准在两个 epoch 的完整重放、每种校准文件篡改、结束轮失败、
嵌套审计隔离、类型敏感比较与基准诊断负例。native/fixture 测试不是双 ISA 生产验收。

## 3. 重新建立 wrapper

复用底层 Phase95 QEMU，所有外层 wrapper 必须按新代码重建。不要编辑旧 backend 的摘要。
逐条运行，每条状态 0 后才执行下一条。

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

要求三者 build-status 的 stage=complete、complete=true；校准分别为 control 10、atomic 138、LRSC 68。
`semanticApproval=false` 正常：后端准备完成不授予用户程序语义验收。

## 4. 同版本正确性与性能 A/B，先小规模再长矩阵

新增两个种子覆盖 Phase136 的真实 3/4 参数、不同指针/输入位置，以及 LRSC next 活跃返回。
没有按种子名称选择翻译策略。也可用任意满足支持前提的输入重复以下实验。

```bash
for KIND in atomic lrsc
do
  case "$KIND" in
    atomic)
      INPUT="$REPO/experiment/inputs/l3-atomic-call-xor.c"
      BACKEND="$RV2X86_L3_ATOMIC_BACKEND"
      ;;
    lrsc)
      INPUT="$REPO/experiment/inputs/l3-lrsc-call-next.c"
      BACKEND="$RV2X86_L3_LRSC_BACKEND"
      ;;
  esac
  {
    time python3 experiment/run_atomic_performance_comparison.py \
      --kind "$KIND" --input "$INPUT" \
      --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$BACKEND" \
      --output "$CHECK_ROOT/ab-$KIND" --repeats 1 \
      --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
      --wall-timeout-seconds 7200 > "$CHECK_ROOT/ab-$KIND.log" 2>&1
  } 2> "$CHECK_ROOT/ab-$KIND-resource.txt"
  AB_STATUS=$?
  printf '%s_ab_status=%s\n' "$KIND" "$AB_STATUS"
  cat "$CHECK_ROOT/ab-$KIND/comparison.json"
  cat "$CHECK_ROOT/ab-$KIND-resource.txt"
  if [ "$AB_STATUS" -ne 0 ]; then break; fi
done
```

每种输入均在同代码/后端上分别运行开关 0 和 1，包含完整普通生产、内部审计及新进程独立审计。
要求 complete=true，各 run accepted=true、两个 returnCode 均 0、timedOut=false。
A/B 必须通过实际输入/输出、完整对象、调用辅助实参、样本计划、返回角色和 comparison 一致性检查。
运行特定 token/指针地址不直接跨执行比较，原值仍保存在各自审计证据中。
重试次数不强制相同，但每一次执行原有机器、路径、归因及重试规则均须通过。

speedup > 1 表示本次端到端提升。repeats=1 仅用于预检；论文/稳定性能结论应换新输出目录，
使用 repeats>=3，并保留不同顺序、资源与环境信息。不要把跨进程 span 总和当成 wall time。
性能不如预期时先提供两份 comparison 与 timing summary，不要先删检查或减少样本。

## 5. 拆分计时

```bash
for KIND in atomic lrsc
do
  for MODE in 0 1
  do
    DIR="$CHECK_ROOT/ab-$KIND/repeat-0-mode-$MODE"
    python3 experiment/inspect_validation_timing.py \
      --input "$DIR/production-timing.jsonl" > "$DIR/production-timing-summary.json"
    SUMMARY_STATUS=$?
    printf '%s_mode_%s_production_timing_status=%s\n' "$KIND" "$MODE" "$SUMMARY_STATUS"
    python3 experiment/inspect_validation_timing.py \
      --input "$DIR/audit-timing.jsonl" > "$DIR/audit-timing-summary.json"
    SUMMARY_STATUS=$?
    printf '%s_mode_%s_audit_timing_status=%s\n' "$KIND" "$MODE" "$SUMMARY_STATUS"
    cat "$DIR/production-timing-summary.json"
    cat "$DIR/audit-timing-summary.json"
  done
done
```

重点比较 atomic.base-backend-full-validation、atomic.calibration-full-replay、
atomic.intent-program-replay、atomic.operation-closing-replay，及 atomic/lrsc 的
compiler-and-proof-binding、build-side、deployment-independent-rebuild、capture、independent-replay、standalone-audit。
共享入口现有 joint.* 标签仍可能出现在 atomic 的 JSONL 中，这不是联合机制被自动批准。
`returned=true` 仅表示该计时函数正常返回；计时报告 semanticApproval=false 正常。

## 6. Phase136 新功能的 12 项生产验收

A/B 正常后执行。本组还保留原有负例；不能用运行耗时替代验收结果。

```bash
{
  time python3 -m pytest -vv -rs --durations=0 \
    pytools/tests/test_l3_extended_call_production.py \
    --basetemp="$CHECK_ROOT/extended-pytest" \
    --junitxml="$CHECK_ROOT/extended.xml" > "$CHECK_ROOT/extended.log" 2>&1
} 2> "$CHECK_ROOT/extended-resource.txt"
EXTENDED_STATUS=$?
printf 'extended_status=%s\n' "$EXTENDED_STATUS"
tail -n 90 "$CHECK_ROOT/extended.log"
cat "$CHECK_ROOT/extended-resource.txt"
```

要求 12 passed、无 skipped：4 AMO、4 LRSC、4 control。

## 7. 既有功能的 51 项生产兼容回归

```bash
{
  time python3 -m pytest -vv -rs --durations=0 \
    pytools/tests/test_l3_atomic_production.py \
    pytools/tests/test_l3_lrsc_production.py \
    pytools/tests/test_l3_lrsc_live_production.py \
    pytools/tests/test_l3_control_production.py \
    --basetemp="$CHECK_ROOT/compat-pytest" \
    --junitxml="$CHECK_ROOT/compat.xml" > "$CHECK_ROOT/compat.log" 2>&1
} 2> "$CHECK_ROOT/compat-resource.txt"
COMPAT_STATUS=$?
printf 'compat_status=%s\n' "$COMPAT_STATUS"
tail -n 110 "$CHECK_ROOT/compat.log"
cat "$CHECK_ROOT/compat-resource.txt"
```

要求 51 passed、无 skipped：18 直接 AMO、27 LRSC（old/next/status）、6 control。
pytest 生产测试最后故意篡改轨迹验证拒绝，因此不能把它们的目录当作未损坏性能 A/B 输入。
A/B 脚本自己创建的目录保持独立，不能复用覆盖输出目录。

若需排除开关对其它种子的影响，可以额外用 RV2X86_ATOMIC_PERFORMANCE=0 在新目录运行选择性生产项，
保留同样的审计/负例；不要求为了计时再无条件重跑全部数小时矩阵。

## 验收结论的范围

通过以上步骤可验收本轮性能策略、Phase136 调用基础子域及原有生产支持域兼容性。
不能据此宣布 M4/M5 全部完成：一般原子地址/类型、多活跃输出、新操作族、原子联合上下文、
一般对象控制流、带合流与回边的 CFG、有界循环和动态完整审计等仍见 Phase136 缺口表。
本地没有真实 Clang10/RISC-V GCC/QEMU 环境，真实加速倍数与双 ISA 通过状态必须由上述宿主实验给出。

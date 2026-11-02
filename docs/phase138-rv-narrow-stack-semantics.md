# Phase138：RV64 窄栈访问与完整 LR/SC 外壳核验

基线：Phase137 `67faff805522da7c917d56e662874f92662ba504`。
分支：`phase138-rv-narrow-stack-semantics`。

## 已确认错误与本轮修订

宿主 Phase137-MsKEpT 的 LRSC A/B 在关闭优化模式下失败：
`L3_CONTROL_MACHINE_OPCODE_UNSUPPORTED:243:0x1086a`。
GCC7 -O0 的完整 78 字节函数确认该位置为 `sw a5,-60(s0)`，保存 uint32_t 辅助参数。
L0/L1/L2 verified，L3 在 deployment 阶段阻塞，尚未进入该轮 L3 捕获。

修订前，源端外壳 decoder 不接受 SW，step 又固定只接受 64 位栈访问。
扩展调用合同与机器外壳观察能力没有同步，是本轮修复对象。
核心实现没有测试名、地址、寄存器分配或固定机器码匹配。

| 实现 | 本轮行为 |
| --- | --- |
| RV64 普通整数访存 | 解码 SB/SH/SW/SD、LB/LH/LW/LD/LBU/LHU/LWU；访存仍必须绑定 stack，未接通一般对象访问 |
| 压缩外壳 | 新增 C.LW/C.SW/C.LWSP/C.SWSP，保留旧 LD/SD；拒绝保留编码与截断指令 |
| 字宽转换 | ADDIW/C.ADDIW 实现低 32 位运算、回绕和 64 位符号扩展；加载区分符号/零扩展；AMD64 32 位 MOV 保持零扩展 |
| 栈状态 | 小端逐字节保存常量或带位置信息的符号投影；只更新实际写入字节，精确处理重叠 |
| 完整身份 | 未破坏的完整 64 位往返可恢复原符号身份；部分值、混合来源值不会自动成为完整参数或指针 |
| 未定义/未证明状态 | 未定义字节加载拒绝；无法证明 stack 基址仍拒绝；没有把未知值当相等 |
| 持久化 | 导出 JSON 原生符号表达式，往返后逐类型比较和具体值重放；不靠 Python tuple/list 宽松相等 |
| 诊断 | 未支持指令附原始字节；LRSC 前后缀解码失败标明 prefix/suffix |

栈保存还核对了 AMD64 PUSH RSP 的先读取旧值、再更新栈指针顺序，并有原生机器执行对照。

完整 LR/SC 序列、ordering、对象/输入绑定、返回角色、目标 CAS 不变式、实际轨迹、重试限制、栈恢复和独立审计门槛保留。
没有将错误指令当 NOP，没有跳过无用参数存储，也没有修改源程序以绕开错误。
Phase137 的性能开关和首次/结束两轮核验策略保持不变。

原重叠写入测试的保守“整个旧槽失效”预期改为更强的字节语义检查：
明确核对部分覆盖后的正确混合值，并继续拒绝含未定义字节的加载。
这不是允许读取旧值；新的独立具体值参考检查用于防止错误重构。

本轮不是通用 ISA 解释器，也不是完整 M4/M5 交付；一般对象控制流、任意算术/指令、ABI 类型扩展、
原子联合上下文、有界循环及其它尚未建立的证明能力仍不能由本轮结果自动结清。
当前栈模型也不等于完整的栈内存安全证明。

语义依据：
- https://docs.riscv.org/reference/isa/v20240411/unpriv/rv64.html
- https://docs.riscv.org/reference/isa/v20240411/unpriv/c-st-ext.html

## 本地验证记录

- 综合回归：1123 passed、16 skipped，209.52 秒。
- 最终相关专项：227 passed、16 skipped，19.49 秒；与综合范围重叠。
- 最终字节/共享 control 模型测试：75 passed、16 skipped，0.42 秒，包含原生 PUSH RSP 执行；与上述范围重叠。
- 16 skipped 为本地缺少真实 RISC-V 交叉编译器；没有把字节 fixture 当作实际编译或执行成功。
- 63 项真实生产均因未选择校准后端而 skipped，不能记为通过。
- 5 个变更 Python 文件通过 Python 3.10 AST 检查；git diff --check 通过。
- 原失败 78 字节函数通过完整 source() 核验；错误绑定、返回角色、重叠指针及栈恢复变体继续拒绝。
- 当前没有本轮真实双 ISA 验收或新性能提升结论。

## 验证安排

不要覆盖 Phase137-MsKEpT 的失败目录。该目录保留为修复前证据。
先完成新增字节/编译回归，再重建 wrapper，并优先运行原失败 LRSC 的 A/B。
A/B 两种模式使用同一份已修复解释器，不能拿有缺陷的旧解释器与新解释器比较加速。

## 1. 更新与环境

先结束正在运行的旧版本实验，保留其目录。运行中切换实现会正确触发摘要拒绝。
Bash 下激活 `.venv-l2` 后执行：

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase138-rv-narrow-stack-semantics
git switch --track origin/phase138-rv-narrow-stack-semantics
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_ATOMIC_PERFORMANCE=1
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase138-XXXXXX")"
export TIMEFORMAT=$'wall_seconds=%R\nuser_seconds=%U\nsystem_seconds=%S'
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

同名本地分支已存在时，改用 `git switch phase138-rv-narrow-stack-semantics`，随后
`git merge --ff-only origin/phase138-rv-narrow-stack-semantics`。
本宿主已确认编译器为 /usr/bin/riscv64-linux-gnu-gcc-7，新增真实编译测试显式选用该路径。
若该路径改变，应指定实际交叉编译器；显式配置无效会报错，不能通过跳过来验收。
不清理已有 build 修改。本轮未修改 C++ 前端，无需为 Python 性能变化重新编译前端。
本指南使用 Bash `time`，不依赖缺失的 `/usr/bin/time`。

## 2. 快速正确性回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_narrow_stack.py \
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

要求退出码 0、无失败；本宿主的 16 项真实 RISC-V 编译测试应实际执行，不应 skipped。
这些测试检查 -O0/-O2、rv64g/rv64gc 及不同参数位置、返回角色的真实 ELF，仍不同于双 ISA 生产验收。
检查其它 skipped 的具体原因，不能把 skipped 当通过。
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
for KIND in lrsc atomic
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
for KIND in lrsc atomic
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

## 完成条件与范围

1. 快速回归无失败，宿主真实 RISC-V 编译测试没有被跳过。
2. 新 wrapper 准备完整；保持 atomic 138、LRSC 68 校准覆盖。
3. 原失败 LRSC 输入在模式 0 和 1 下均完成 L0--L3 及新进程独立审计；A/B complete=true。
4. AMO A/B 及 12 项新增、51 项既有生产回归通过且无 skipped。
5. 保留 comparison、JUnit、资源统计和原始证据；时间摘要不授予语义批准。

原失败机器码在本地通过解释与证明检查，只能说明已修复该模型阻塞。
实际 GCC/QEMU 完整工作链、性能收益和更广兼容性仍以上述宿主实验为准。

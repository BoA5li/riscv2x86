# Phase139：原子寄存器调用与 LR/SC 减法的增量闭环

基线：Phase138，远端提交 `659076dc8c84066eb98b3bbec85ab19ffe443569`。
分支：`phase139-atomic-register-call-closure`。

**这是 A、E 的部分实现，不是全部 A–G 的完成交付；M4/M5 不能据此结清。**
没有删除单片段、对象边界、函数效应、输出活跃性或动态控制流的原有拒绝条件。

## 实际变更

1. `register_call_abi.py` 明确 RV64 LP64 与 AMD64 SysV 的整数参数寄存器。
   原子调用上限取两端交集六个参数；不把栈参数、浮点、向量或聚合 ABI 当作支持。
   编译器入口检查、调用合同、L2 harness、L3 spec 和机器符号初态同步扩展至 5/6 参数。
   类型、参数声明、对象及实际实参继续校验，辅助参数继续记录。
   共享 control 初态默认仍为四个参数；只有显式参数数量才能取得额外寄存器事实。
2. 当前双参数编译器快照若含 typed signature，也必须校验；损坏、null 或重哈希的错误 signature
   不能回落到旧路径。旧快照缺少 signature 时，保留原来的双参数检查；不改旧 v1/v2 报告形状。
   额外参数的调用仍必须有完整编译器 signature。此兼容措施不代表所有调用接口已统一。
3. LR→SUB/SUBW→SC→失败回边的闭合序列，贯通源解码、源状态、目标合同、符号证明、渲染、
   L2 结果比较、最终目标机器 CAS 两轮重算、L3 实际结果比较、intent 规划及持久化重放。
   SUBW 限 LR.W/SC.W；next 保留完整 XLEN 符号扩展，存储仅取访问宽度低位。
   减法严格为 old-input；不应用 ADD/AND/OR/XOR 的交换律。逆序源操作数和目标 SUB→ADD 篡改拒绝。
   直接 RISC-V AMO 注册集合仍为五类；没有虚构 AMOSUB 指令或仅添加一个操作名称。
4. 原子性、ordering 和失败回边继续依赖原来的证明及真实机器归因。
   校准仍为 control 10、AMO 138、LRSC 68；减法本身的算术正确性由源/目标证明与结果比较承担，
   既有 LR/SC、CAS 校准承担相同宽度及 ordering 位下的 callback 机制，不把校准当语义证明。
   不把参考 status/next 填入实际寄存器观察；失败 SC 状态也不假定为 1。

新增生产项有 8 项：4 项第 5/6 参数 AMO，4 项 LR/SC 减法调用/返回角色。
旧扩展生产 12 项和旧兼容生产 51 项保留。生产测试保留独立审计及篡改后拒绝检查。

## A–G 清算：尚未实现的部分

| 项目 | 本分支状态 | 仍需实现与代码位置 |
| --- | --- | --- |
| A：统一调用及活跃输出 | 部分 | `atomic_call_contract` 仍为单个 unsigned 对象、受限整数类型；`lrsc_output_observation.return_role()` 仍只接一个直接 C 返回。多指针、多输出、表达式消费、signed/聚合 ABI 尚未接通 |
| B：地址、对象与别名 | 未完成 | `memory_address_projection.project_memory_address()` 与 `atomic_memory_binding.validate_binding()` 仍要求 exact dereference/零偏移；须同时完善表达式来源、范围、对齐、别名、harness 和最终机器地址归因 |
| C：全函数效应闭包 | 未完成 | `compiler_continuation_sites.atomic_function_scope()` 仍为单 asm 外壳；普通 C 访存、计算及控制效应需编译器效应图和可重放证明，不能靠函数签名授权 |
| D：原子联合上下文及整体审计 | 未完成 | `l3_execution_plan.build()` 仍只在单 finding 分派 atomic/LRSC；`l3_joint_spec.spec()` 不接原子/control 成员；验收入口仍有对应单片段限制 |
| E：更多操作/序列 | 部分 | 本轮增加有完整合同的闭合减法序列；仍是固定四指令区域。其它操作族、额外指令与多分支序列没有被自动批准 |
| F：CFG、合流、多出口和对象控制 | 未完成 | `compiler_program_regions.export()`、`joint_reaching_definitions.derive()` 仍为直接无环/线性值版本；需要编译器 CFG、路径条件、确定赋值、数据及内存合流 |
| G：循环与动态观察 | 未完成 | `l3_control_machine.graph()` 仍拒绝循环；`runtime/l3_qemu_program_trace.c` 仍使用固定 next_region。需要循环不变式/边界依据、动态实例协议和完整路径审计，不能仅提高预算或允许重复 PC |

以上剩余项是实现依赖缺失，不能解释成已完成、只等更多日志。单独路线的通过不能代替联合执行。
建议后续实现顺序是 B/C 的共同对象及效应图 → D 的单次调用联合路线 → F 的无环 CFG/合流 →
G 的有证明循环和动态实例；A 的多输出需在实际消费者能观察后接通，E 每个新族均贯穿全部证明层。
每一步都需要正例、反例、变形例、持久化重放及新进程审计后才能声明相应支持域完成。

## 本地验证范围

本地具备 native GCC，缺少真实 RISC-V 编译器和校准 QEMU 后端。
新增测试核验实际 native 返回、完整对象及最终机器码，不把 fixture 当作双端执行。
宿主真实 RISC-V 编译测试覆盖 -O0/-O2、rv64g/rv64gc、参数位置及返回角色；本地缺工具时会明确 skipped。
显式指定的编译器路径无效会失败。生产测试缺后端也会 skipped，不能作为验收通过。
本分支没有新增性能优化，也没有新的加速比结论；原有首次/结束核验和独立审计隔离策略保持。

本地最终综合回归：1486 passed、24 skipped，124.81 秒。24 skipped 均为真实 RISC-V 编译测试。
新增专项及共享 control 检查：257 passed、24 skipped，与综合回归重叠，不累计计数。
新增生产 8 项、既有生产 63 项已核对收集数量，尚未在本地进行真实双端验收。
22 个变更/新增 Python 文件通过 Python 3.10 AST 语法检查，8 个 Bash 命令块通过 bash -n，
git diff --check 通过。

## 1. 更新和环境

停止旧代码下仍在运行的实验，保留旧输出目录。不要清理已有 build 修改。
本分支没有修改 C++ 前端，无需仅因 Python 变化重编译它。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase139-atomic-register-call-closure
git switch --track origin/phase139-atomic-register-call-closure
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export RV2X86_ATOMIC_PERFORMANCE=1
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase139-XXXXXX")"
export TIMEFORMAT=$'wall_seconds=%R\nuser_seconds=%U\nsystem_seconds=%S'
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

同名本地分支已经存在时使用 `git switch phase139-atomic-register-call-closure`，再
`git merge --ff-only origin/phase139-atomic-register-call-closure`。

## 2. 快速正确性、证明及兼容回归

```bash
python3 -m pytest -q -rs \
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

要求退出码 0、无失败。宿主 24 项真实 RISC-V 编译测试应执行，不能以 skipped 验收。
先处理任何失败，再运行耗时生产矩阵。

## 3. 重新准备版本绑定后端

可以复用 Phase95 底层 QEMU。外层 wrapper 固定整个 Python 包，必须重建；不能编辑旧摘要。
以下命令逐条执行，每条退出码 0、日志及 build-status 完成后才执行下一条。

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

## 4. 新增 8 项真实生产及负例审计

```bash
{
  time python3 -m pytest -vv -rs --durations=0 \
    pytools/tests/test_l3_extended_call_production.py \
    -k 'register_boundary or subtraction_production' \
    --basetemp="$CHECK_ROOT/new-pytest" \
    --junitxml="$CHECK_ROOT/new-production.xml" > "$CHECK_ROOT/new-production.log" 2>&1
} 2> "$CHECK_ROOT/new-production-resource.txt"
NEW_STATUS=$?
printf 'new_production_status=%s\n' "$NEW_STATUS"
tail -n 100 "$CHECK_ROOT/new-production.log"
cat "$CHECK_ROOT/new-production-resource.txt"
```

要求 8 passed、无 skipped。每项必须 L0–L3 verified、生产完成、独立审计通过，且层状态/轨迹篡改被拒绝。
这些生产测试最后会主动损坏测试证据，以核验负例拒绝；其目录不适合再次作为未损坏审计输入。

## 5. 既有 63 项兼容生产

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
tail -n 110 "$CHECK_ROOT/compat-production.log"
cat "$CHECK_ROOT/compat-production-resource.txt"
```

要求 63 passed、无 skipped：原扩展 12 项加兼容 51 项。不要覆盖旧目录或在测试运行中切换代码。

## 6. 性能模式对等性与未损坏独立审计

此项验证本轮能力扩展不破坏旧性能开关的验收等价性，不预设有新的提速。

```bash
python3 experiment/run_atomic_performance_comparison.py \
  --kind lrsc --input "$REPO/experiment/inputs/l3-lrsc-register-sub-next.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_LRSC_BACKEND" \
  --output "$CHECK_ROOT/ab-subtraction" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --wall-timeout-seconds 7200 > "$CHECK_ROOT/ab-subtraction.log" 2>&1
AB_STATUS=$?
printf 'subtraction_ab_status=%s\n' "$AB_STATUS"
cat "$CHECK_ROOT/ab-subtraction/comparison.json"
```

要求 complete=true，两种模式各 run accepted=true，production/standaloneAudit 均 returnCode=0、未超时。
同一源码、样本、对象、全部实参和返回角色均须比较一致。保留 token/地址各自原证据，不强制重试次数相等。
单次测量仅用于预检；稳定性能结论需要不同顺序及多次重复。时间信息从不授予语义批准。

本轮完成条件仅涵盖本指南明确扩展的寄存器调用及闭合减法序列，不涵盖表中尚未实现的 A–G 剩余部分。

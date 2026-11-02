# Phase135：LR/SC 活跃返回输出与入口绑定

基线：Phase134 `d77b313d98a67ec83b5b5e4eb6d79896cecb2389`。
分支：`phase135-lrsc-live-return-observation`。

**这是 M4 的一个已实现子项，不是 M4/M5 全部完成。**
真实双 ISA 生产验收及性能数据仍须在主机取得。不能把本地 native/fixture 测试记为 QEMU 生产验收。

## 实现及保证

- `lrsc_output_observation.return_role()` 用编译器声明身份和完整 downstream-use 图绑定一个实际 C 返回输出：old、next 或 status。
  其余活跃使用仍拒绝；没有忽略 store、call、branch 或一般 C 表达式消费，没有为了观察而修改用户函数签名。
- L2 使用原有实际函数调用 harness，比较全 64 位返回值和全部对象字节；观察合同明确记录返回角色、访问/算术宽度及实际 C 返回来源。
  直接 AMO 的旧接口不变。LR/SC 当前要求 unsigned XLEN 返回，未批准的转换仍不进入该接口。
- L3 规格的新增输出使用 v2 并固定 returnRole；旧 old 规格保持 v1 字段。
  独立部署重建重新派生编译器绑定、侧车、规格和最终机器码，不信任记录中的角色字符串。
- RISC-V 最终机器码检查返回寄存器确实来自指定序列输出；x86 检查完整 CAS 不变式、失败回边、成功后的实际返回表达式及栈恢复。
  word 算术先截断再符号扩展，next 不能用低位存储结果冒充。
- L3 比较实际返回值与批准完成状态，不填造寄存器读数；失败尝试寄存器仍未观察。
  最终 status=0 是完成状态合同，不推断失败 SC 总是返回 1，不要求两侧重试次数相同，不声称并发进展或物理内存序实测。
- atomic/LRSC 部署按精确 functionId 选择唯一入口并重新检查编译器事实。
  已批准 sole-asm scope 仍排除调用和其它效应；不再因翻译单元存在未调用的无关函数直接拒绝。
  不支持可达 callee，不扩张成调用图闭包。整个源文件、目标重写及机器码摘要检查不变。
- 修正控制符号执行中把任意 tuple 当 stack 的错误：零位移复制保持值身份，非零位移只对明确 stack 或整数值成立。
  未知值算术仍拒绝。这不是 M5 循环支持。

新模块由现有全 Python 包摘要自动纳入后端固定依赖。不能修改旧 manifest 摘要来兼容新代码。
本轮没有更改缓存、重试预算、样本数量、校准或审计策略；继承 Phase134 性能实现，不另行声称 LR/SC 加速。

## 尚未完成的工作

| 子项 | 仍存在的门槛 | 实施前必须建立的合同 |
| --- | --- | --- |
| M4 地址和调用 | atomic_memory_binding、atomic spec、retry machine 仍固定零偏移、两个参数和一个对象 | 编译器地址表达式、对象范围/对齐、统一调用、harness、每次访问归因与独立比较一起扩展 |
| M4 多输出 | 本轮只观察一个直接返回输出，其它活跃消费仍拒绝 | 既有 C 可观察输出路径的类型/版本合同；不能注入假寄存器读数 |
| M4 新操作族 | 直接 RMW 五类；LR/SC 四类 ALU | 每族的解码、规范语义、上游证明、renderer、机器机制校准、L2/L3 比较与反例 |
| M4 混合上下文 | joint spec/execution plan/审计尚未支持 atomic 与其它成员联合闭包 | 一次调用的共享对象状态、原子内部尝试子轨迹、跨成员义务和整体审计 |
| M5 编译器图 | compiler_program_regions/compiler_joint_scope 仍为直接无环外壳 | 编译器区域 CFG、路径条件、数据/内存版本、出口和全部可达效应 |
| M5 路径与循环 | control 图拒绝回边；program plugin 固定区域顺序 | 独立版本动态轨迹、区域实例、边/迭代身份、路径相关对象与输出观察 |
| M5 有界性 | 当前观测预算不构成循环证明 | 循环不变式、ranking/bound、迭代内对象范围及无 C UB 条件；超预算只能 incomplete |
| M5 审计 | 尚无跨控制区域整体独立重放 | 从原始证据重建路径、迭代、对象状态、退出及所有要求，拒绝遗漏/重复事件 |

先建立共享调用与区域图合同，再交付地址/多输出、无环 memory+control、多出口、最后有界循环。
目前不缺普通成功日志作为这些算法的依据；缺的是上述实际证明和观察实现。性能通过也不能结清这些覆盖缺口。

## 本地验证记录

- 本轮最终相关回归：676 passed，79.44 秒，无 skip。
- Phase134 性能实现回归：38 passed，33.19 秒。
- 新增输出专项包含 81 项测试，已经包含在 676 项内，不重复累计。
- 改动 Python 文件通过 Python 3.10 AST 语法检查，git diff --check 无错误。
- 本地无真实 RISC-V GCC/QEMU/Clang10；未运行 27 项真实 LR/SC 生产矩阵，未取得新版本主机性能数据。

## 主机验证

以下为 Bash。每步检查退出码；失败时保存日志，不继续长矩阵。不要覆盖旧结果。

### 1. 更新和快速验证

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase135-lrsc-live-return-observation
git switch --track origin/phase135-lrsc-live-return-observation
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase135-XXXXXX")"
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
cmake --build build > "$CHECK_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$CHECK_ROOT/build.log"
```

已存在同名本地分支时使用 git switch，再 git merge --ff-only origin 对应分支。保留本地 build 修改，不使用 reset --hard。

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_lrsc_live_return.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_lrsc_persistence.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_control_machine.py \
  pytools/tests/test_l3_control_spec.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 60 "$CHECK_ROOT/focused.log"
```

要求无 failed/error；本地验证中这组无 skip。native 执行以及 fixture 不替代后续双 ISA 验收。
新增测试覆盖两宽度/四运算/addw、三个返回角色、O0/O2、每个实例 64 组边界输入，错误返回角色、错误高位、额外活跃用途、不完整枚举、重复入口拒绝。

### 2. 新建校准 wrapper

底层 Phase95 QEMU/backend 可复用；control、LRSC、atomic、joint 固定了受影响文件，必须重新生成。
底层来源验证失败应先处理来源问题，不能修改旧摘要或绕过校验。

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_control_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/control-backend" > "$CHECK_ROOT/control-backend.log" 2>&1
CONTROL_STATUS=$?
printf 'control_backend_status=%s\n' "$CONTROL_STATUS"
tail -n 30 "$CHECK_ROOT/control-backend.log"
```

control 成功后：

```bash
python3 -m riscv2x86_py.l3_lrsc_backend \
  --control-backend "$CHECK_ROOT/control-backend/backend.json" \
  --output "$CHECK_ROOT/lrsc-backend" > "$CHECK_ROOT/lrsc-backend.log" 2>&1
LRSC_BACKEND_STATUS=$?
printf 'lrsc_backend_status=%s\n' "$LRSC_BACKEND_STATUS"
tail -n 30 "$CHECK_ROOT/lrsc-backend.log"
cat "$CHECK_ROOT/lrsc-backend/build-status.json"
export RV2X86_L3_LRSC_BACKEND="$CHECK_ROOT/lrsc-backend/backend.json"
```

要求 complete=true、stage=complete、全部校准完成；semanticApproval=false 正常。

### 3. 先跑两个新增生产实例

```bash
python3 -m pytest -vv -rs \
  'pytools/tests/test_l3_lrsc_live_production.py::test_live_return_production_and_independent_audit[next-32-add-True]' \
  'pytools/tests/test_l3_lrsc_live_production.py::test_live_return_production_and_independent_audit[status-64-xor-False]' \
  --basetemp="$CHECK_ROOT/live-smoke-pytest" \
  --junitxml="$CHECK_ROOT/live-smoke.xml" \
  > "$CHECK_ROOT/live-smoke.log" 2>&1
LIVE_SMOKE_STATUS=$?
printf 'live_smoke_status=%s\n' "$LIVE_SMOKE_STATUS"
tail -n 80 "$CHECK_ROOT/live-smoke.log"
```

要求 2 passed、无 skip。每例实际完成普通生产、L0–L3、独立审计及证据篡改拒绝，且含未调用的无关函数。

### 4. 完整 LR/SC 矩阵

```bash
/usr/bin/time -v -o "$CHECK_ROOT/lrsc-production-resource.txt" \
  python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_lrsc_live_production.py \
  pytools/tests/test_l3_lrsc_production.py \
  --basetemp="$CHECK_ROOT/lrsc-production-pytest" \
  --junitxml="$CHECK_ROOT/lrsc-production.xml" \
  > "$CHECK_ROOT/lrsc-production.log" 2>&1
LRSC_STATUS=$?
printf 'lrsc_production_status=%s\n' "$LRSC_STATUS"
tail -n 100 "$CHECK_ROOT/lrsc-production.log"
cat "$CHECK_ROOT/lrsc-production-resource.txt"
```

要求 27 passed、无 skip：新增 next/status 各 9，既有 old 9。不要将 skip 当作通过。
函数未改变签名；输出依然来自实际调用。实际 SC 失败次数不要求跨架构相同。

### 5. 直接 AMO 回归

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$CHECK_ROOT/control-backend/backend.json" \
  --output "$CHECK_ROOT/atomic-backend" > "$CHECK_ROOT/atomic-backend.log" 2>&1
ATOMIC_BACKEND_STATUS=$?
printf 'atomic_backend_status=%s\n' "$ATOMIC_BACKEND_STATUS"
tail -n 30 "$CHECK_ROOT/atomic-backend.log"
export RV2X86_L3_ATOMIC_BACKEND="$CHECK_ROOT/atomic-backend/backend.json"
```

backend 成功后：

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_atomic_production.py \
  --basetemp="$CHECK_ROOT/atomic-production-pytest" \
  --junitxml="$CHECK_ROOT/atomic-production.xml" \
  > "$CHECK_ROOT/atomic-production.log" 2>&1
ATOMIC_STATUS=$?
printf 'atomic_production_status=%s\n' "$ATOMIC_STATUS"
tail -n 80 "$CHECK_ROOT/atomic-production.log"
```

要求 18 passed、无 skip。control 使用新 control backend 按既有配置回归，不能复用过期 wrapper。

### 6. joint 功能与继承性能验收

用本代码重新生成 joint wrapper 后执行 Phase134 指南的小负载、93 布局 A/B 和 10+20 joint 矩阵。
具体完整命令见 [Phase134 指南](phase134-joint-provenance-performance.md)，把其中 CHECK_ROOT 和分支更新步骤替换为本轮路径；不覆盖旧目录。
A/B 使用 --comparison-scope phase134，同一输入/后端、相同样本布局和事件数，两模式均需完整生产及新进程审计。
首次 repeats=1 只作回归预检；需要报告稳定性能结论时 repeats>=3，并保留逐次墙钟、资源和 timing 文件。
不能使用旧版本不支持的新 next/status 用例作为速度提升的基线。新增 LR/SC 暂无性能提升声明。

通过以上实验只能结清本轮明确实现的返回观察子域及回归；不能将 M4 地址、新操作族或 M5 循环记为完成。

# Phase132：联合值版本、别名布局覆盖与快照消费优化

基线远端提交：`c257d8fea7087946c6ec8aa5e5a288492b73728b`。
分支：`phase132-joint-definitions-and-layouts`。

## 交付边界

本轮实现了 M2 的两项基础缺口：直接联合区域的 reaching definitions，以及多指针联合别名布局与实际采样闭合。
同时减少了同一次编译器快照消费中的重复读取，继承 Phase131 的操作内后端校验优化和计时。
**完整 M2/M3 尚未完成**：单 asm 多访存效应、一般地址/值表达式和其它 fence 合同仍需贯通其源模型、候选、证明、渲染、观察和独立审计。
本轮没有开放这些缺乏完整链路的路线。总体方案仍见 `phase131-m2-m3-completion-plan.md`。

## 实现与正确性依据

### 1. 联合定义版本

`joint_reaching_definitions` 只消费编译器确认的直接、无环、无其它 C 操作的联合外壳。
所有区域都必须存在并精确匹配源码范围。每个 GNU 槽的输入/输出角色来自 frontend constraints 与 Clang carrier 的重新闭合，不能从裸 AST 猜测分区。

读取发生在当前 asm 的所有输出定义之前。纯输出覆盖旧版本，后续消费者仅连接最近定义，最终 return 只绑定实际到达返回点的版本。
已在覆盖前消费的旧值仍保留其使用；有证明的未使用输出才标为 discarded。未知或不完整使用保留拒绝。
重复声明作为同一个 asm 的不同输入槽时，各槽有独立的 use/value node，不再因同名声明产生错误歧义。
编译器原始枚举仍须包含相应 producer/consumer 使用，缺失不会被忽略。

`l2_fragment_execution` 使用这些重建事实生成依赖图、观察边界与 discard 义务；旧的非联合路线不改变算法。
`l3_joint_spec` v3 绑定整个 `valueFlowContract`，独立部署/审计重建该合同。输入未定义、输出冲突、缺少区域、错误 frontend join、使用遗漏都不能闭合。
这不是包含任意 CFG、循环或 callee 的 SSA 实现；这些程序仍由原来的域限制准确拒绝。

### 2. 兼容类型的联合布局

`object_layout_contract` v2 对最多四个指针视图生成所有类型兼容的集合分区。
每个共享分组构造同址、正向/反向对齐交叠、边界相接的有限偏移代表，剔除无法完整观察或超过资源界限的构造，并规范化去重。
类型兼容性目前仍要求完全相同的未限定整数 pointee；未擅自接受跨类型别名、restrict、volatile 或 atomic 对象。

默认同类型自动对象下：

| 指针数 | 类型兼容分区数 | 有限布局数 |
| --- | ---: | ---: |
| 2 | 2 | 5 |
| 3 | 5 | 17 |
| 4 | 15 | 93 |

不同类型或对象尺寸/对齐可改变布局数。分区覆盖不等于穷尽所有字节偏移、数值或语言对象类型。
各视图来自真实 typed allocation；共享存储的更新一次后投影全部视图，不以不同 objectId 推断 noalias。

`joint-sample-plan` v3 保证每个声明布局至少安排一次调用，默认 8 是最少样本数。
样本不足时扩展到布局数，而不是静默遗漏。值仍是有限样本，不声称每个布局穷尽所有整数值。
每次计划明确列出布局对应的样本，实际样本数量和轨迹由既有重放/审计核验。

QEMU 联合观察插件的调用容量从 32 增至 256，仍保留完整边界与最多 4096 次访存的限制。
生成器同步检查 256 样本和 4096 访存预算；超过预算准确拒绝，不截断后宣称完成。
重放从实际样本数重建计划应逐字段相同；路线还用原配置重新生成计划，拒绝请求与旧捕获混用。

### 3. 性能优化

旧 `l3_joint_deployment.bound` 对每个成员重新读取源文件、报告、编译器快照，并重复验证整个快照。
新 `compiler_bound_findings` 在一次操作中读取报告和快照各一次，验证快照整体身份，然后对每个成员执行原有全部 closure/type/provenance 检查。
返回前重新核验源码、报告和快照摘要，期间修改任何输入均拒绝。没有跨运行缓存，也没有用一个成员的成功覆盖其它成员。

这减少文档读取/解析和源摘要的重复工作，不代表完整验证只剩一次。真实编译、L2/L3 执行、部署重建、逐成员证明、原始轨迹检查和独立审计仍保留。
Phase131 的完整后端初检/末检仍存在。新增 `joint.compiler-snapshot-batch-consumption` 计时可用于检查实际贡献。
验收摘要只简化已 verified 层的显示，完整证据仍在原始报告中；失败层 detail 与独立审计不被省略。

## 验证范围

新增本地测试覆盖：同一输出变量被重定义、旧值此前已消费、最终返回归属、两个输入槽读取同一版本、窄/宽对象和共享别名后的重载；所有类型兼容分区、全部布局计划、真实 93 次原生调用；实际 C 插件 callback 的 33/93/256 次边界和第 257 次拒绝；错误角色/缺少使用/缺少区域/未初始化输入；快照批量消费与逐成员消费一致、修改任一输入和坏成员拒绝。
这些原生执行与编译器/证明 fixture 是测试适配，不是实际 RISC-V/x86 生产批准。
本地扩大回归为 **437 passed、4 skipped**（缺少真实 Clang 的 AST 检查）；最终目标回归为 70 passed、14 skipped，其中额外 10 项是缺少真实双 ISA 后端的生产测试。
两次运行范围重叠，不合并为总通过数量；尚未取得本轮真实生产矩阵或端到端加速结论。
新增 4 项真实 production 测试覆盖 16/64 位、3/4 指针、同变量重定义、可选普通 rw/rw fence、完整独立审计和篡改原始事件后的拒绝。
真实矩阵需要在实验主机执行。

## 主机实验

逐块运行；失败时保留 CHECK_ROOT，不继续依赖失败结果的步骤。以下不使用 exit，也不清理已有实验与 build 修改。

### A. 更新与环境

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase132-joint-definitions-and-layouts
git switch --track origin/phase132-joint-definitions-and-layouts
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase132-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
cmake --build build > "$CHECK_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$CHECK_ROOT/build.log"
```

如分支已存在，改用 `git switch phase132-joint-definitions-and-layouts`。预期 build_status=0。

### B. 快速回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_joint_definitions_layout_coverage.py \
  pytools/tests/test_compiler_snapshot_batch_consumption.py \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_multi_object_joint.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_joint_typed_access.py \
  pytools/tests/test_l3_joint_fence_context.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$CHECK_ROOT/focused.log"
```

预期无 failure/error。真实 Clang 存在时 AST 检查不应因环境缺少而跳过。

### C. 重新生成联合后端

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/backend-timing.jsonl"
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" \
  > "$CHECK_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 50 "$CHECK_ROOT/joint-backend.log"
cat "$CHECK_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
```

必须 complete=true、12 项校准完成。后端 semanticApproval=false 正常；程序批准来自完整工作链。
实现文件和插件已变化，应按本轮重新生成，不修改旧后端摘要绕过陈旧检查。

### D. 四视图 smoke 与独立审计

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/smoke-timing.jsonl"
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-redefined-four-views.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/four-view-smoke" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  > "$CHECK_ROOT/four-view-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
cat "$CHECK_ROOT/four-view-smoke/run-status.json"
```

只有 status=0、stage complete、三个完成标志 true、blockers=[] 后继续。

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/audit-timing.jsonl"
python3 experiment/inspect_joint_acceptance.py \
  --root "$CHECK_ROOT/four-view-smoke" \
  > "$CHECK_ROOT/four-view-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/four-view-audit.log"
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/smoke-timing.jsonl" \
  > "$CHECK_ROOT/smoke-timing-summary.json"
cat "$CHECK_ROOT/smoke-timing-summary.json"
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/audit-timing.jsonl" \
  > "$CHECK_ROOT/audit-timing-summary.json"
cat "$CHECK_ROOT/audit-timing-summary.json"
```

预期 4 成员全部 L0–L3 verified，独立审计 verified、programExecutionUnitCount=1。
本输入为 93 布局、每端 93 次实际调用、372 次访存事件，fenceEvents=0。不得继续按旧 8 样本检查。
计时中成功的新捕获操作仍应包含 2 次完整联合后端校验、24 次校准检查；其它独立操作另有校验。

### E. 新生产矩阵及兼容性

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/production-timing.jsonl"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_definitions_production.py \
  pytools/tests/test_l3_multi_object_production.py \
  --basetemp="$CHECK_ROOT/production-pytest" \
  --junitxml="$CHECK_ROOT/production.xml" \
  > "$CHECK_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$CHECK_ROOT/production.log"
```

预期 10 passed、无跳过。各例包含独立审计及原始轨迹篡改的拒绝；故意篡改的测试目录不作为干净验收归档，保留 D 的 smoke。

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/compat-timing.jsonl"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_production.py \
  --basetemp="$CHECK_ROOT/compat-pytest" \
  --junitxml="$CHECK_ROOT/compat.xml" \
  > "$CHECK_ROOT/compat.log" 2>&1
COMPAT_STATUS=$?
printf 'compat_status=%s\n' "$COMPAT_STATUS"
tail -n 100 "$CHECK_ROOT/compat.log"
unset RV2X86_VALIDATION_TIMING
```

预期 20 passed，无 failure/error/skipped。

### F. 性能解释

先提供 smoke/audit 两个计时摘要，再决定剩余优化重点。包含时间和子阶段不能相加，跨进程累加不是 wall time。
四视图现有 93 调用比旧 8 调用承担更多覆盖，不能用这两者直接声称加速或退化。性能前后比较应采用共同支持、相同样本和布局的程序。
推荐共同域输入 `l3-joint-load-add-store.c`：单指针、8 调用，按 D 的命令另开输出目录执行并独立审计。
保留相同工具链、后端校准策略和机器负载条件；旧实现用其匹配的代码与后端独立运行，不能将陈旧后端换摘要后复用。
没有主机实测前不承诺具体加速比例。批量快照读取的优化由读取次数和失效测试证实，端到端贡献需要真实计时。

## 未完成项及继续实施依据

| 剩余项 | 当前真实阻塞 | 继续工作的必要交付 |
| --- | --- | --- |
| 单 asm 多效应 | source memory/value facts、memory candidate/proof/renderer、L2/L3 spec 仍是单访问合同 | 有序内存状态程序、全输出/完整 shell 证明、目标实现、逐效应观察、完整独立审计 |
| 一般地址和值表达式 | joint scope 仍消费直接声明和受限 uint64 载体；复杂表达式没有完整调用/输出闭包 | 类型化求值、次数/顺序、对象内地址与边界、转换、lvalue、返回及同步部署/重放 |
| 其它普通 fence | SourceFenceOrdering 和 full fence 路线仍只批准 rw/rw | 按源掩码分别证明，明确 exact/strengthened 策略，真实机制校准、比较和审计 |
| 环境属性 | 用户态普通内存 callback 不能观察设备顺序或指令发布完成 | 明确 local/cross-hart 发布与 runtime，或具体设备/MMIO 合同，再实施真实环境路线 |

这些普通内存和 fence 条目仍是开发工作，不能归因于缺少通用实验日志；环境路线另需具体目标合同。
本轮验收通过只能关闭本文已交付子项，不能将 M2/M3 整体状态改为 completed。

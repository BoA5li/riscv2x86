# Phase131：性能优化验收指南

本轮只优化重复后端校验、增加计时，并提供 M2/M3 剩余实现方案；未开放新的翻译语义域。
方案见 `phase131-m2-m3-completion-plan.md`。不以本轮通过宣布 M2/M3 已全部完成。

本地扩大回归为 406 passed、4 skipped（缺少真实 Clang 的 AST 检查）。
这些原生/适配测试没有代替真实 RISC-V/x86 主机验收，也不提供端到端加速结论。

## 1. 更新与准备

逐块运行。失败时保留日志，不继续依赖它的步骤。以下命令没有 `exit`，`set +e` 不会因测试返回非零关闭交互终端。
保留本地 build 变化，不执行 reset/clean。若同名分支已经存在，使用 `git switch phase131-joint-validation-performance`。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase131-joint-validation-performance
git switch --track origin/phase131-joint-validation-performance
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
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase131-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
cmake --build build > "$CHECK_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$CHECK_ROOT/build.log"
```

预期 build_status=0。旧的联合后端绑定旧 Python 实现，本轮必须新建联合后端，不手改旧文件或摘要。Phase95 基础后端的固定实现文件没有在本轮修改，可继续验证后复用。

## 2. 快速回归和失效检查

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_multi_object_joint.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l3_joint_typed_access.py \
  pytools/tests/test_l3_joint_fence_context.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_versioned_joint_closure.py \
  pytools/tests/test_joint_harness_call_shapes.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$CHECK_ROOT/focused.log"
```

预期无 failure/error。实验主机具有真实 Clang 时，相关 AST 测试不应因缺少 Clang 跳过；本地编辑环境的适配测试不能替代它。
新增测试检查操作内复用、结束前完整复查、后端/依赖变动拒绝、不同操作不复用、默认 capture 前后检查、计时异常不遮蔽验证错误。

## 3. 新建带计时的后端

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

必须 status=0、complete=true、stage=complete、12 项校准完成。semanticApproval=false 是后端不单独授予程序语义批准的正常状态。

## 4. 一个真实多对象 smoke，先取得性能分布

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/smoke-timing.jsonl"
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-multi-object-alias.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --timeout-seconds 240 \
  --l3-producer-timeout-seconds 600 \
  --output "$CHECK_ROOT/multi-smoke" \
  > "$CHECK_ROOT/multi-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
cat "$CHECK_ROOT/multi-smoke/run-status.json"
```

只有 smoke_status=0、complete、三个完成标志 true、blockers=[] 后继续。

单独计时独立审计，避免把审计和生产耗时混合：

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/audit-timing.jsonl"
python3 experiment/inspect_joint_acceptance.py \
  --root "$CHECK_ROOT/multi-smoke" \
  > "$CHECK_ROOT/multi-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
tail -n 80 "$CHECK_ROOT/multi-audit.log"
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/smoke-timing.jsonl" \
  > "$CHECK_ROOT/smoke-timing-summary.json"
TIMING_STATUS=$?
printf 'timing_status=%s\n' "$TIMING_STATUS"
cat "$CHECK_ROOT/smoke-timing-summary.json"
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/audit-timing.jsonl" \
  > "$CHECK_ROOT/audit-timing-summary.json"
cat "$CHECK_ROOT/audit-timing-summary.json"
```

预期审计 verified、programExecutionUnitCount=1、每成员 L0–L3 verified，仍为每端 8 样本、32 访存/屏障事件、8 fence 事件。
smoke 计时摘要中成功 newCaptureOperations 应有 backendValidationCalls=2、calibrationChecks=24（两次完整后端检查，各 12 项）。
外层加载、后续成员和独立审计仍有各自校验，不要求整个日志里只有两次。
正常完成应无 incompleteParentSpans；被中断的进程可能留下未完成父跨度，不能拿不完整计时做加速结论。

`inclusiveSeconds` 包含子阶段，不可与子阶段相加。`exclusiveSeconds` 扣除已插桩子跨度，但仍可能含未插桩工作；不等于纯 CPU 时间。
不同进程的时间会重叠，不能把它们相加当作实验 wall time。需要真实前后对比时使用相同工具链、相近机器负载和相同用例/参数，保留各自原生后端与完整结果。
本轮不提供未经主机测量的加速百分比。请先提供这两个计时摘要和 smoke/audit 日志，再判断剩余重建是否是主导瓶颈。

## 5. 生产与反例矩阵

smoke 和独立审计通过后再运行。无需安装并行插件，也不降低样本数；每组单独计时文件。

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/multi-matrix-timing.jsonl"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_multi_object_production.py \
  --basetemp="$CHECK_ROOT/multi-pytest" \
  --junitxml="$CHECK_ROOT/multi-production.xml" \
  > "$CHECK_ROOT/multi-production.log" 2>&1
MULTI_STATUS=$?
printf 'multi_status=%s\n' "$MULTI_STATUS"
tail -n 100 "$CHECK_ROOT/multi-production.log"
```

预期 6 passed、无跳过。各例末尾会故意删除自己的原始事件并要求独立审计拒绝；这些负例目录不作为干净归档，保留上面的 clean smoke。

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/compat-timing.jsonl"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_production.py \
  --basetemp="$CHECK_ROOT/compat-pytest" \
  --junitxml="$CHECK_ROOT/compat-production.xml" \
  > "$CHECK_ROOT/compat-production.log" 2>&1
COMPAT_STATUS=$?
printf 'compat_status=%s\n' "$COMPAT_STATUS"
tail -n 100 "$CHECK_ROOT/compat-production.log"
unset RV2X86_VALIDATION_TIMING
```

预期 20 passed、无 failure/error/skipped。这些矩阵仍含真实构建及多次独立重放，可能继续较慢；先分析 smoke 再决定是否立即运行全部。
计时数据只用于效率诊断，所有生产完成条件仍由原验证器与独立审计决定。

## 6. 本轮与后续阶段的完成边界

本轮完成条件：回归通过、真实 smoke/audit 完成、原始证据篡改被拒绝、矩阵兼容、校验调用次数符合预期，并得到真实耗时分布。
剩余 M2/M3 仍按方案实施：定义版本→单 asm 多效应→布局/表达式扩展→其它普通 fence→环境合同及整体清算。
请保留 CHECK_ROOT 路径；无需再次采集庞大的全仓库 basis 文本。

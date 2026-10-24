# Phase96：L3 生产测试目录隔离与失败诊断

基于 Phase95 `060ee9c59a03416bb95abde7c928639bd45d5f2c`。

## 根因与修订

真实生产重命名测试把 arbitrary_file.c 放在 tmp_path，同时把 production 放进 tmp_path。单文件的源码根目录取其父目录，评估器正确拒绝源码根目录内的 work。两个参数化配置都在编排阶段停止，尚未运行轨迹篡改负测。

测试改为 inputs/arbitrary_file.c 与 production 同级。保留实际前端、构建、两端 QEMU、四层 verified、实际事件与中央审计断言；不放宽源码隔离或语义准入。

L3 驱动在独立验收前记录 normal_production_result、batchLogPath、caseDiagnostics。诊断保留 detail、orchestrationFailure、attempts/layers、案例报告路径。批处理非零时保持失败，不运行独立验收。成功但缺少汇总、失败且缺少汇总分别记录明确原因；报告路径必须位于 batch 内。空案例不构成验收成功。独立审计失败仍保持失败且保留案例诊断。

仅修复目录布局和失败报告；不改变观察器、合同、证明、缓存模型、中央 closer 或支持域。默认 clang 的自动能力选择尚未实现，本机显式 PATH 选择 Clang10。旧 Phase33 wrapper 已不存在，不再使用该路径。

## 主机验证

在 .venv-l2 中执行；输出目录使用新目录，不覆盖旧证据。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10="/usr/bin/clang-10"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE96_ROOT="$(mktemp -d "$REPO/experiment/results/phase96-XXXXXX")"
hash -r
printf 'PHASE96_ROOT=%s\n' "$PHASE96_ROOT"
cmake --build build -j2 > "$PHASE96_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE96_ROOT/build.log"
```

构建返回 0 后：

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_batch_evaluation_cli.py \
  --junitxml="$PHASE96_ROOT/focused.xml" \
  > "$PHASE96_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 60 "$PHASE96_ROOT/focused.log"
```

快速测试通过后执行真实生产测试：

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE96_ROOT/production.xml" \
  > "$PHASE96_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE96_ROOT/production.log"
```

必须为 2 passed、0 skipped。每项先完成四层真实验收，再故意篡改自己的临时轨迹，要求审计拒绝。成功的测试临时目录因此不宜再作为完整正向证据。原始输入应在新目录另跑，不带模型和带模型各一次；沿用 Phase95 命令但改为新的 output。无需重建未变更的 backend；消费者仍会核查其身份。

失败时读取 pytest 报告内的新 production 路径中的 run-status.json，查看 currentStage、steps、batchLogPath、caseDiagnostics 与 blockers。生产非零不能按完成报告。

之后才进行旧 016/022/024/029 组合兼容性验证与最终回归。恢复此前真实 controlled-system、controlled-time、local-sync 配置；新增 RV2X86_L3_TRACE_BACKEND，并运行 verify_route_contracts.py --require-no-regression-skips。原始输入与重命名测试成功不等于全部 32 例 L3 覆盖，更不等于物理微架构等价。

## 开发环境验证边界

驱动生命周期测试使用模拟子进程和审计器，仅验证错误处理、失败不转成功和诊断保存，不提供真实 L3 证据。主机上的两项真实生产测试必须单独通过。

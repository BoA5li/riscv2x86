# Phase 84：CSR 读取覆盖与受控 TIME 验收

分支：`phase84-csr-access-coverage`。基线：`506a0ddb2c56ad355b6f0ed3f6ecc948ec8f5c11`。

## 修复范围

decoder 的 typed effect 使用机器指令首个 p-code 索引；旧版 SLEIGH 的 TIME COPY
可能位于前置临时操作之后。原先用两个索引去重，会把同一次读取追加为不完整的
derived effect，继而触发 `TIME_USER_EXECUTION_SCOPE_UNSUPPORTED` 和无批准状态。

现在按机器指令归属及完整 CSR→结果寄存器读取覆盖关联。覆盖检查复用既有
`architectural_state_reads`：一条已声明的只读操作、正确 alias/位宽/结果寄存器，
只允许纯临时计算。额外读取、写入、其他 CSR、未知副作用或控制流不被该覆盖吞掉。
保留 typed effect 的原有索引和身份，不迁移现有合同、结果流及 dataflow 身份。
其他既有显式元数据消费路径保持原规则；本轮没有宣称新增通用 CSR 写入能力。

消费检查先报告 `MECHANISM_TRANSLATION_NOT_APPROVED` 及上游原因；获批但消费不一致
仍拒绝，并记录比较细节。`run-status.json.failureDiagnostics` 保存原因、报告路径
及诊断。执行事实完整性与 privileged-state 完整性分开报告。backend/runner 缺失、
manifest 无效或二进制摘要不一致在 bootstrap 前拒绝；检查不授予语义批准。

测试包含旧 SLEIGH 规范化形态到字段证明、批准重放、合同消费，真实 pypcode→CFG→
执行语义分析，寄存器变化及额外读写、错误结果、位宽、控制流、未知操作负测。
它们不冒充真实 QEMU 完整生产验收。受控 TIME 仍只证明逻辑读取轨迹及结果流；
原生 TIME、完整时钟模型、跨 hart 与 L3 不在完成声明中。

本轮机器可读测试记录见 `experiment/baselines/phase84/validation-summary.json`。
当前开发环境缺少 LLVM frontend/交叉编译器/QEMU，真实生产测试跳过；必须在实验
主机完成以下验收后才能声明完整路线通过。扩大范围检查还发现基线已有失败，
基线与修订版本逐项比较，不能将这些失败省略后声称全库全绿。

## 1．更新与准备

以下各段分别执行并检查状态；不使用 `set -e`、`exit`、reset 或 clean。
本地源码修改先保存，不强制覆盖。已成功构建的独立 backend 不需重新构建。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
git status --short
git fetch origin phase84-csr-access-coverage
git switch --track origin/phase84-csr-access-coverage
git rev-parse HEAD

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PREVIOUS_ROOT="$REPO/experiment/results/phase83-production-ToHPRs"
export PHASE84_ROOT="$(mktemp -d "$REPO/experiment/results/phase84-XXXXXX")"
printf 'PHASE84_ROOT=%s\n' "$PHASE84_ROOT"

cmake --build build -j2 > "$PHASE84_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE84_ROOT/build.log"
```

已有本地同名分支时改用 `git switch phase84-csr-access-coverage`，再执行
`git pull --ff-only origin phase84-csr-access-coverage`。后续仅在构建成功时继续。

复用旧输入的前提：原始源码未改，实际执行域与 CPU 约束仍成立，backend、二进制及
trace header 身份仍匹配。若前提改变，按 Phase 83 准备流程重新生成相应输入。
驱动会重新准备绑定合同与 provider，不复用旧批准。

```bash
export RV2X86_CONTROLLED_QEMU_MANIFEST="$PREVIOUS_ROOT/controlled-qemu/backend.json"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON="$(python3 -c 'import json,os; print(json.dumps([os.path.join(os.environ["PREVIOUS_ROOT"],"controlled-qemu/build/qemu-riscv64"),"-L","/usr/riscv64-linux-gnu"]))')"
export RV2X86_LOCAL_SYNC_DECLARATION="$PREVIOUS_ROOT/sync-selection.json"
export RV2X86_QEMU_SOURCE="$REPO/qemu"
export RV2X86_QEMU_BUILD="$REPO/qemu/build"
export RV2X86_NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
python3 -m json.tool "$RV2X86_CONTROLLED_QEMU_MANIFEST"
```

## 2．先执行 029 完整路线

```bash
python3 experiment/run_mechanism_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output "$PHASE84_ROOT/time-complete" \
  --architecture-template "$PREVIOUS_ROOT/architecture.json" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --time-mode controlled --time-review "$PREVIOUS_ROOT/time-selection.json" \
  --time-backend "$RV2X86_CONTROLLED_QEMU_MANIFEST" \
  --time-runner-json "$RV2X86_CONTROLLED_QEMU_RUNNER_JSON" \
  > "$PHASE84_ROOT/time-driver.log" 2>&1
TIME_STATUS=$?
printf 'time_status=%s\n' "$TIME_STATUS"
tail -n 40 "$PHASE84_ROOT/time-driver.log"
cat "$PHASE84_ROOT/time-complete/run-status.json"
```

要求返回 0、`completedRoutes=["time"]`、`productionAcceptanceComplete=true`、
`blockers=[]`，并且 acceptance 中 L0/L1/L2 均 verified。bootstrap 和中间 approval
批处理允许返回 1；只有最后的配置运行及中央检查可以建立完整成功。
失败先读 `currentStage`、`blockers`、`failureDiagnostics` 及对应阶段日志，保留失败。

## 3．组合验收（029 完整成功后）

```bash
python3 experiment/run_mechanism_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --output "$PHASE84_ROOT/combined" \
  --architecture-template "$PREVIOUS_ROOT/architecture.json" \
  --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" \
  --sync-declaration "$RV2X86_LOCAL_SYNC_DECLARATION" \
  --qemu-source "$RV2X86_QEMU_SOURCE" --qemu-build "$RV2X86_QEMU_BUILD" \
  --native-runner-json "$RV2X86_NATIVE_RUNNER_JSON" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --time-mode controlled --time-review "$PREVIOUS_ROOT/time-selection.json" \
  --time-backend "$RV2X86_CONTROLLED_QEMU_MANIFEST" \
  --time-runner-json "$RV2X86_CONTROLLED_QEMU_RUNNER_JSON" \
  --suite "$REPO/experiment/generated-suite" \
  > "$PHASE84_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE84_ROOT/combined-driver.log"
cat "$PHASE84_ROOT/combined/run-status.json"
cat "$PHASE84_ROOT/combined/suite-preservation.json"
```

要求返回 0、两条路线完成、整体 acceptance complete、保持性记录存在且原成功案例
均保持成功。该驱动强制检查选定案例、L0/L1/L2、实际证据与中央审计；套件检查按
实际 inventory 绑定输入，不按案例编号授予翻译许可。裸基线仍应缺合同而拒绝。
受控 TIME 与原生/局部同步环境分别报告，不能把 28 verified 解读为原生严格等价。

## 4．最终回归：启用真实生产测试并拒绝跳过

上面的环境变量启用两个 renamed-function 真实生产测试。缺变量时它们原本会跳过；
本轮最终验收用 `--require-no-regression-skips` 阻止把这种回归当成完整验收。

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE84_ROOT/regression" --require-no-regression-skips \
  > "$PHASE84_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 30 "$PHASE84_ROOT/regression-driver.log"
tail -n 15 "$PHASE84_ROOT/regression/regression.log"
cat "$PHASE84_ROOT/regression/run-status.json"
```

这里不再重复裸套件；组合运行已包含相同 inventory 的裸基线与配置套件。
要求 regression 返回 0 且无 skipped，与组合验收成功共同作为本轮通过条件。

## 日志查询

```bash
find "$PHASE84_ROOT" -name '*approval-consumption.json' -print -exec cat {} \;
find "$PHASE84_ROOT" -name '*provider-audit.log' -print -exec cat {} \;
find "$PHASE84_ROOT" -name 'production-acceptance.json' -print -exec cat {} \;
```

翻译拒绝时查看该阶段 `cases/*/work/translation-work/translated_report.json` 的
`translationReasonCodes`、`routeAuthorityDiagnostics` 和 `contract-consumption.json`；
构建/执行失败查看对应 `evaluation-result.json`、`work/replay` 及 provider invocation。
文件不存在时先确认驱动是否执行到该阶段。旧失败目录不覆盖，重试用新的 output。
不关闭 sanitizer，不手写 approval，不将 read-stream 成功升级为完整 TIME 或 L3。

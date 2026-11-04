# Phase143：SYSTEM L3 证据消费、汇总与统计闭环

基线：Phase142 `1f605f94fd491911e1be6175f34233b0a17a57c5`。
分支：`phase143-system-l3-evidence-consumers`。

## 修订范围

宿主的 ecall/wfi 案例均已获得 L0–L3 verified，专用独立审计也通过；但旧批量
汇总只接受 fragmentResult/platformReports，因没有识别 SYSTEM 专用证据而将
L3 降级为 inconclusive，触发 SYSTEM_RUN_PRODUCTION_NOT_VERIFIED。

本次增加统一 SYSTEM 策略消费入口，重新执行既有完整独立审计，核对权威需求
及全部四项性质，再生成专用的 bounded summary。它不是通用平台报告，不能
作为输入替代原始证据。未知 schema、缺失性质、重复成员、错误策略、变更程序、
不完整前置层、错误环境和类型均不能获准。无测试文件名、函数名或路径匹配。

- 批量：保留通用证据的原有 fail-closed 闭包，单独消费受控 SYSTEM 证据；
  还要求唯一 staged requirement sidecar 与实际案例需求严格一致。
- 统计：增加 boundedSystemIntentVerified 和 l3BoundedSystemVerifiedProgramCount，
  不增加 architecturalIntentVerified 或 target diagnostic 的成功数。
- 论文：L3 层记录 bounded_verified；单列 bounded SYSTEM 的片段和验证单元指标。
  它不进入原有无条件体系结构意图 L3 分子。
- 状态：验收文件分别记录 independentResultAuditComplete、batchSummaryComplete；
  两者均完成才允许 productionAcceptanceComplete 为 true。批量失败依然非零退出。
- 诊断：外层失败记录包含案例原因、逐层汇总和覆盖诊断。
- 保留源码证明、receipt、六种构建重建、机器机制、原始观察、环境与程序绑定。
  统计消费执行审计存在实际开销，本轮不宣称性能提升。

声明范围仍为 bounded-controlled-environment-intent。不宣称原生 Linux 用户态
等价、物理微架构等价或 M6/M7 全面完成。通用调用图组合、指令可见性 L3 等
既有缺口没有在本轮被标记完成。

## 1. 更新并建立新实验目录

停止正在运行的实验后操作。保留本地 build、pyc 和全部历史结果，不执行 reset/clean。
本轮未修改 C++ 前端、受控内核或运行库源码。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase143-system-l3-evidence-consumers
if git show-ref --verify --quiet refs/heads/phase143-system-l3-evidence-consumers; then
  git switch phase143-system-l3-evidence-consumers
  git merge --ff-only origin/phase143-system-l3-evidence-consumers
else
  git switch --track origin/phase143-system-l3-evidence-consumers
fi
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase143-XXXXXX")"
hash -r
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
cat "$CHECK_ROOT/git-head.txt"
```

切换或合并失败则先处理具体错误，不在旧分支继续。修订绑定实现身份，旧验收结果
只能用于诊断，不能修改其 hash、状态或原始证据充当新版本的验收。

## 2. 消费层、反例与既有逻辑回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_policy_evidence.py \
  pytools/tests/test_l3_system_route.py \
  pytools/tests/test_system_entry_scope.py \
  pytools/tests/test_compiler_call_dependencies.py \
  pytools/tests/test_compiler_call_inventory.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_execution_environment_closure.py \
  pytools/tests/test_configured_environment_suite.py \
  pytools/tests/test_experiment_environment.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_l3_batch_coverage.py \
  pytools/tests/test_batch_evaluation_cli.py \
  pytools/tests/test_paper_evaluation.py \
  pytools/tests/test_l3_authoritative_consumption.py \
  pytools/tests/test_l3_evidence_closure.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l2_provider_artifacts.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$CHECK_ROOT/focused.log"
```

要求零 failed/error。宿主已具备 Clang，应执行相应真实编译器测试；若 skipped，
先阅读原因，不能将跳过解释为通过。合成证据/替身回归不代替下面真实生产实验。

## 3. 重新验证已有 SYSTEM 后端

使用已知的宿主后端作为输入，生成新目录，保留旧目录。不要手动更新身份字段。

```bash
export OLD_SYSTEM_BACKEND="$REPO/experiment/results/phase142-cCgLNd/system-backend/backend.json"
python3 -m riscv2x86_py.controlled_system_backend upgrade-backend \
  --backend "$OLD_SYSTEM_BACKEND" \
  --output "$CHECK_ROOT/system-backend" \
  > "$CHECK_ROOT/system-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'system_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$CHECK_ROOT/system-backend.log"
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$CHECK_ROOT/system-backend/backend.json"
```

仅在 backend_status=0 后继续。若依赖或构建环境不符，保留错误信息；不可跳过
校验、改写旧 hash 或悄悄替换运行器。

## 4. 真实 SYSTEM L3 生产矩阵

```bash
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/system-l3-timing.jsonl"
TIMEFORMAT='wall_seconds=%R user_seconds=%U system_seconds=%S'
{ time python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_system_production.py \
  --basetemp="$CHECK_ROOT/system-l3-pytest" \
  --junitxml="$CHECK_ROOT/system-l3-production.xml"; } \
  > "$CHECK_ROOT/system-l3-production.log" 2>&1
SYSTEM_L3_STATUS=$?
unset RV2X86_VALIDATION_TIMING
printf 'system_l3_status=%s\n' "$SYSTEM_L3_STATUS"
tail -n 140 "$CHECK_ROOT/system-l3-production.log"
```

要求 **2 passed，0 skipped/failed/error**，退出码 0。测试现在同时断言：

- 外层生产完成，所有执行/审计/受控 L3 标志为 true，blockers 为空；
- 案例和批量均 verified，L0–L3 全部 verified；
- 受控成功计数为 1，通用体系结构成功计数与 notRun 为 0；
- 验收文件的独立审计、批量汇总和整体完成三个标志均为 true；
- 新进程独立审计通过，损坏实际程序或缺失前置层后拒绝。

bootstrap 未配置时 unsupported、approval 中间阶段未闭环，可与最终 configured
通过同时存在；最终 configured 若仍 inconclusive 则不能继续宣称修复完成。

## 5. 单独核验实际产物与全链状态一致性

此命令会重新执行实际产物独立审计，不仅检查保存的成功标签。

```bash
python3 experiment/inspect_system_l3_acceptance.py \
  --root "$CHECK_ROOT/system-l3-pytest" \
  --expected-runs 2 \
  > "$CHECK_ROOT/system-consistency-audit.json" 2>&1
AUDIT_STATUS=$?
printf 'system_consistency_audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/system-consistency-audit.json"
```

要求退出码 0、productionRunCount=2、evaluationCount=2、errors=[]，
productionAcceptanceComplete=true。每项声明范围为受控 SYSTEM；物理等价声明
为 false。脚本也可对单个 production 目录使用 --expected-runs 1。

## 6. 旧 SYSTEM L0–L2 路线回归

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_controlled_system_production.py \
  --basetemp="$CHECK_ROOT/system-legacy-pytest" \
  --junitxml="$CHECK_ROOT/system-legacy.xml" \
  > "$CHECK_ROOT/system-legacy.log" 2>&1
LEGACY_STATUS=$?
printf 'legacy_system_status=%s\n' "$LEGACY_STATUS"
tail -n 100 "$CHECK_ROOT/system-legacy.log"
```

要求 **2 passed、0 skipped/failed/error**。此旧路线的 L3 保持 not_run，不能
为了统一结果而将旧路线升级标记为 SYSTEM L3。

## 7. 时间记录与结果回传

```bash
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/system-l3-timing.jsonl" \
  > "$CHECK_ROOT/system-l3-timing-summary.json"
TIMING_STATUS=$?
printf 'timing_status=%s\n' "$TIMING_STATUS"
cat "$CHECK_ROOT/system-l3-timing-summary.json"
```

优先返回 git-head.txt、focused.log、system-backend.log、
system-l3-production.log、system-consistency-audit.json、system-legacy.log、
system-l3-timing-summary.json。无需压缩包，可分段粘贴文本。

本轮以修复验收正确性为目标，没有删减审计工作，也不承诺更短运行时间。
嵌套 inclusive span 和跨进程工作量不可相加当作 wall time。功能全部通过后，
再在同策略、同输入和相同审计义务下分析性能，不与旧 L0–L2 不同工作量直接比较。

## 发布前本地验证

- 19 文件回归：301 passed、2 skipped（缺少真实 Clang），15.35 秒。
- 新增消费/汇总/论文指标/宿主核验脚本回归：22 项，包含在上述结果中。
- 两项新 SYSTEM L3 和两项旧路线生产测试均可收集；当前执行环境无宿主的
  显式 SYSTEM 后端，未在此执行，须按第 3–6 步完成真实宿主验收。
- 修改的 Python 文件均通过 Python 3.10 语法解析；七个 Bash 代码块通过 bash -n；
  git diff --check 无错误。最后 CLI 完整性条件调整后的针对性回归：72 passed。

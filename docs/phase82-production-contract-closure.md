# Phase 82：机制合同消费与生产验收

基线提交：`3b0bafe2a627bfca3323330fd19d7d6cfee6095a`。
新分支：`phase82-production-contract-closure`。

开发环境验证：扩展后的选定回归为 **874 passed、41 skipped**，无失败。
跳过项依赖缺少的真实前端/ISA 工具；原始 024/029 生产运行与受控 QEMU 构建
尚未在此开发环境执行。协议夹具测试、真实 native helper 执行不能替代这项验收。
本地工具齐全后，以实际运行和中央审计结果为准，不要求复现相同跳过数。

## 修改与边界

本轮修复准备与验收链的缺口，不把未配置的输入改成默认获准：

* 准备工具重新验证 compiler snapshot、源摘要、候选闭合、GNU operand shell
  和观察 scope。CSR 静态 witness 重新通过 decoder/compiler join 构造并比较，
  不能仅依靠重新计算一个诊断记录的 hash。
* 执行事实产生独立诊断：架构解释已绑定不等于访问事实完整。原语义检查及
  `needs_route` 保留；诊断记录不授予翻译许可。
* 消费记录核对实际源文件；实验驱动在绑定 provider 前重放批准及所选 registry，
  并核对磁盘中的消费记录。未消费的合同不能进入正向验收。
* 观察用源 DSO 使用 provider 所绑定的 source compiler，拒绝冲突配置。
* 新增 `architecture / contracts / approval` 暂停点、`currentStage` 与
  `productionAcceptanceComplete`。暂停点成功返回 0 只代表该检查完成，
  `completedRoutes` 仍为空，不代表完整生产验收。
* 最终单例要求 program L0/L1/L2、typed L2 及中央审计。全套配置运行另外执行
  中央审计，并要求选定案例仍 verified、既有 verified 案例不退化。
* 新增实际局部同步生产测试；和受控时间生产测试一样，缺少明确选择的真实环境
  时跳过，不以协议夹具替代真实验收。

局部同步支持一个已绑定函数、单线程、局部 pinned hart、私有普通一致性内存，
无外部写者/别名/MMIO/正在执行的代码覆盖。有限观察对象范围不代表全程序机制证明。
扩展函数形态、跨 hart 发布需要新的合同与非干扰依据。

严格 TIME 新路径仍限定显式受控环境。原生 QEMU/RDTSC 严格后端未实现，
`--time-mode native` 仅可用于架构诊断；完整路径准确拒绝。原有功能性路径不改名。
本轮不声明 wall-time 或 L3 等价。不要自动把环境选择、hash 或文件存在当成语义证明。

## 1．更新和构建

保留本地源码修改与实验目录，不运行 reset/clean。先执行：

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
REPO="$PWD"
git status --short
git fetch origin phase82-production-contract-closure
git switch --track origin/phase82-production-contract-closure
git rev-parse HEAD
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
mkdir -p "$REPO/experiment/results"
PHASE82_ROOT=$(mktemp -d "$REPO/experiment/results/phase82-XXXXXX")
cmake --build build -j2 > "$PHASE82_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\nPHASE82_ROOT=%s\n' "$BUILD_STATUS" "$PHASE82_ROOT"
tail -n 60 "$PHASE82_ROOT/build.log"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
```

如果本地已经有此分支，改用 `git switch phase82-production-contract-closure`，
然后 `git pull --ff-only origin phase82-production-contract-closure`。
每一段检查状态后再执行依赖它的下一段；不把这些命令作为整段自动脚本粘贴。

## 2．小范围回归和架构检查

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_mechanism_route_closure.py \
  pytools/tests/test_mechanism_experiment_driver.py \
  pytools/tests/test_controlled_time.py \
  pytools/tests/test_visibility_provider_preparation.py \
  > "$PHASE82_ROOT/focused-tests.log" 2>&1
TEST_STATUS=$?
printf 'focused_tests_status=%s\n' "$TEST_STATUS"
cat "$PHASE82_ROOT/focused-tests.log"

python3 -m riscv2x86_py.prepare_mechanism_selection architecture \
  --privilege-spec riscv-privileged-1.12 --xlen 64 \
  --extensions i zicsr zifencei \
  --output "$PHASE82_ROOT/architecture.json"
ARCH_STATUS=$?
printf 'architecture_selection_status=%s\n' "$ARCH_STATUS"
```

然后只运行架构诊断，不需要时间 backend 或同步声明：

```bash
python3 experiment/run_mechanism_routes.py \
  --frontend "$REPO/build/riscv2x86" \
  --output "$PHASE82_ROOT/architecture-check" \
  --architecture-template "$PHASE82_ROOT/architecture.json" \
  --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --stop-after architecture
CHECK_STATUS=$?
printf 'architecture_checkpoint_status=%s\n' "$CHECK_STATUS"
cat "$PHASE82_ROOT/architecture-check/run-status.json"
cat "$PHASE82_ROOT/architecture-check/time-static-checkpoint.json"
```

预期 `preparedRoutes` 包含所选路线，`completedRoutes` 为空，
`productionAcceptanceComplete=false`。029 架构应 bound、静态 join 应 closed；
访问缺失仍显示为独立阻塞。任何静态输入/闭合失败先定位，不继续构建 backend。

也可独立检查旧报告，不改写它：

```bash
python3 -m riscv2x86_py.mechanism_route_checks \
  --source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --report "$REPO/experiment/results/phase81-diagnosis-AIamjs/time-architecture-only/cases/case_029_b2290047d8/work/translation-work/translated_report.json" \
  --family time --output "$PHASE82_ROOT/old-time-checkpoint.json"
```

## 3．024：显式选择适用域，逐阶段运行

先自行写好依据记录，例如 `$PHASE82_ROOT/sync-basis.txt`。必须解释源 QEMU 的
SMC/TB 机制、目标 CPUID helper 的适用协议，以及所选线程/内存域为何成立。
不得用空文件或占位保证替代依据。该记录供审查；摘要只绑定其内容。

```bash
taskset -pc $$
read -r -p '实验责任人：' EXPERIMENT_OWNER
read -r -p '当前允许的 CPU 编号：' SYNC_CPU
python3 -m riscv2x86_py.prepare_mechanism_selection local-sync \
  --owner "$EXPERIMENT_OWNER" --basis "$PHASE82_ROOT/sync-basis.txt" \
  --cpu "$SYNC_CPU" --domain local-private-single-thread \
  --output "$PHASE82_ROOT/sync-selection.json"
SELECTION_STATUS=$?
printf 'sync_selection_status=%s\n' "$SELECTION_STATUS"
NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
```

先检查合同消费与批准，尚不执行最终观察：

```bash
python3 experiment/run_mechanism_routes.py \
  --frontend "$REPO/build/riscv2x86" \
  --output "$PHASE82_ROOT/sync-approval-check" \
  --architecture-template "$PHASE82_ROOT/architecture.json" \
  --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" \
  --sync-declaration "$PHASE82_ROOT/sync-selection.json" \
  --qemu-source "$REPO/qemu" --qemu-build "$REPO/qemu/build" \
  --native-runner-json "$NATIVE_RUNNER_JSON" --stop-after approval
SYNC_APPROVAL_STATUS=$?
printf 'sync_approval_status=%s\n' "$SYNC_APPROVAL_STATUS"
cat "$PHASE82_ROOT/sync-approval-check/run-status.json"
cat "$PHASE82_ROOT/sync-approval-check/sync-approval-consumption.json"
```

应有 `disposition=consumed`；暂停点本身仍不报告生产完成。成功后重用相同输入，
将 output 改为新的 `$PHASE82_ROOT/sync-complete`，将 `--stop-after approval`
改为 `--stop-after complete`，执行完整路径。检查 `sync-provider-audit.log`
和 `productionAcceptanceComplete=true`。每次输出目录保持独立，不覆盖旧结果。

## 4．029：选择受控环境后才构建 backend

如果目标是原生 QEMU/RDTSC 严格等价，请停在架构诊断并继续后端设计；
不能以以下受控实验结果替代原生环境结论。

若明确选择受控实验，先写 `$PHASE82_ROOT/time-basis.txt`：共同外部轨迹、单线程、
无异步读取者、轨迹/日志资源隔离，以及不声明原生 TSC/耗时/L3 等价。

```bash
python3 -m riscv2x86_py.prepare_mechanism_selection controlled-time \
  --owner "$EXPERIMENT_OWNER" --basis "$PHASE82_ROOT/time-basis.txt" \
  --environment shared-external-time-trajectory \
  --output "$PHASE82_ROOT/time-review.json"
TIME_SELECTION_STATUS=$?
printf 'time_selection_status=%s\n' "$TIME_SELECTION_STATUS"

TIME_BACKEND_ROOT="$REPO/experiment/toolchains/phase82-time-$(date -u +%Y%m%dT%H%M%SZ)"
export TIME_BACKEND_ROOT
python3 -m riscv2x86_py.prepare_controlled_time_backend \
  --qemu-source "$REPO/qemu" --output "$TIME_BACKEND_ROOT" --jobs 2
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
cat "$TIME_BACKEND_ROOT/build-status.json"
```

成功后生成 runner JSON，再运行批准检查：

```bash
TIME_RUNNER_JSON=$(python3 - <<'PY'
import json, os
print(json.dumps([os.environ['TIME_BACKEND_ROOT']+'/build/qemu-riscv64',
                  '-L','/usr/riscv64-linux-gnu']))
PY
)
python3 experiment/run_mechanism_routes.py \
  --frontend "$REPO/build/riscv2x86" \
  --output "$PHASE82_ROOT/time-approval-check" \
  --architecture-template "$PHASE82_ROOT/architecture.json" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --time-mode controlled --time-review "$PHASE82_ROOT/time-review.json" \
  --time-backend "$TIME_BACKEND_ROOT/backend.json" \
  --time-runner-json "$TIME_RUNNER_JSON" --stop-after approval
TIME_APPROVAL_STATUS=$?
printf 'time_approval_status=%s\n' "$TIME_APPROVAL_STATUS"
cat "$PHASE82_ROOT/time-approval-check/run-status.json"
cat "$PHASE82_ROOT/time-approval-check/time-approval-consumption.json"
```

成功后重用输入，output 改为新的 `$PHASE82_ROOT/time-complete`，
暂停参数改为 `--stop-after complete`。核对实际 L0/L1/L2、读取事件及中央审计。

## 5．真实生产回归、全套验收和查询

两条路径分别成功后，选择已有审查文件与 backend：

```bash
export RV2X86_LOCAL_SYNC_DECLARATION="$PHASE82_ROOT/sync-selection.json"
export RV2X86_QEMU_SOURCE="$REPO/qemu"
export RV2X86_QEMU_BUILD="$REPO/qemu/build"
export RV2X86_NATIVE_RUNNER_JSON="$NATIVE_RUNNER_JSON"
export RV2X86_CONTROLLED_QEMU_MANIFEST="$TIME_BACKEND_ROOT/backend.json"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON="$TIME_RUNNER_JSON"

python3 -m pytest -q -rs pytools/tests/test_local_sync_production.py \
  pytools/tests/test_controlled_time_production.py \
  > "$PHASE82_ROOT/production-tests.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_tests_status=%s\n' "$PRODUCTION_STATUS"
cat "$PHASE82_ROOT/production-tests.log"

python3 experiment/verify_route_contracts.py \
  --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" \
  --output "$PHASE82_ROOT/regression" --suite "$REPO/experiment/generated-suite"
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
```

最后合并两个已经单独成功的路径：

```bash
python3 experiment/run_mechanism_routes.py \
  --frontend "$REPO/build/riscv2x86" --output "$PHASE82_ROOT/combined" \
  --architecture-template "$PHASE82_ROOT/architecture.json" \
  --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" \
  --sync-declaration "$PHASE82_ROOT/sync-selection.json" \
  --qemu-source "$REPO/qemu" --qemu-build "$REPO/qemu/build" \
  --native-runner-json "$NATIVE_RUNNER_JSON" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --time-mode controlled --time-review "$PHASE82_ROOT/time-review.json" \
  --time-backend "$TIME_BACKEND_ROOT/backend.json" \
  --time-runner-json "$TIME_RUNNER_JSON" --suite "$REPO/experiment/generated-suite"
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
cat "$PHASE82_ROOT/combined/run-status.json"
cat "$PHASE82_ROOT/combined/suite-preservation.json"
```

该运行会核对两次完整源 inventory 一致，并独立检查配置后全套审计、
所选案例 verified 和旧 verified 集合不退化。不要求非法/未支持输入变绿。
L3 仍独立安排。

查询某次失败，先查看 `run-status.json` 的 currentStage、blockers、steps，
然后查看该 stage 的日志或 checkpoint。通用查询：

```bash
find "$PHASE82_ROOT" -type f \
  \( -name run-status.json -o -name '*checkpoint.json' \
     -o -name contract-consumption.json -o -name evaluation-result.json \) -print
grep -RInE 'failureStage|currentStage|blockers|NOT_CONSUMED|MISMATCH|INCOMPLETE|partial' \
  "$PHASE82_ROOT" --include='*.json' --include='*.log'
```

`semanticApproval=false` 的准备/诊断文件是预期行为；证明许可只来自原有 Phase 6D
及批准重放。不要用手工修改输出或汇总状态跳过失败。所有命令保留返回码，
不使用 set -e、shell exit 或清理旧实验目录的操作。

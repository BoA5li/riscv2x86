# Phase 83：真实生产接入、执行环境与验收

分支：`phase83-mechanism-execution-closure`，基线：`cb1031d0887f8d92e49e08d81f315df2f63f977f`。

## 修复与验证结论

实际原始输入运行定位并修复了三处生产缺口：

1. 公开 `suggestedReplacement` 因发布门禁为空，消费者却将它当成获批候选。
   现在从 E0 暂存记录读取文本，验证记录、fragment、批准摘要和一致性，再重放语义批准。
   候选不会因此写入公开字段，也不会因此变成 verified。
2. 024 的 runtime shell 与 L2 shell relation 共用字段，却使用不同身份算法。
   现在从生成批准开始就使用与 L2 authority 相同的规范身份，保留 runtime shell 独立重放。
3. 029 准备时绑定最小默认目标环境，生产管线使用完整目标环境，导致合法合同无法消费。
   两者改为共用生产环境工厂；不忽略环境身份，也不接受近似匹配。

另修复观察用源 DSO 与 L0 原有源对象检查的接入：独立重建 DSO，核对实际字节、
编译器和 RV64 LP64D ELF ABI，然后继续原有源对象和全部 18 个目标构建/执行检查。
L0 新增 `source-rv64-shared-library` 记录。错误产物、ABI 或编译器继续拒绝。

024 机制现在限定已审查的 QEMU/helper 源码实现，未知源码不能靠重算 hash 继承批准。
审查依据见 [local-sync-mechanism-review.md](local-sync-mechanism-review.md)。
执行域仍需符合声明；哈希、reviewer 或探针通过都不能创造环境保证。

两条路线逐案例记录实际环境。024 的 L1 和 L2 使用同一声明的 QEMU 命令、编译器和
CPU 约束；029 的 L1/L2 使用独立受控 backend。中央回读校验层级与外层环境归属。
汇总按 environmentId 区分。受控时间声明见
[controlled-time-validation-scope.md](controlled-time-validation-scope.md)。
它验证受控逻辑读取及结果流，不证明完整 TIME 时钟、原生 TSC 或 L3。

开发验证：选定回归 **918 passed、41 skipped**。这些跳过项未在该回归配置启用真实
生产工具；另外安装 LLVM 10、Ghidra 11.2、交叉工具并构建原生/受控 QEMU 7.2，
实际运行了两个原始输入。源文件摘要与用户提供的原始源文件完全相同。
两者均完成批准重放和合同消费，独立 L1/L2 执行及中央 provider 审计通过。

**完整程序验收仍未通过。** 当前开发宿主的 GCC LeakSanitizer 无法枚举进程任务，
Clang 10 ASan 与宿主 glibc 存在启动兼容问题。L0 矩阵保留这些失败，完整驱动拒绝
将程序提升为 verified。独立执行后续层只用于定位，未修改原失败结果。
真实记录及 sanitizer 明细保存在 `experiment/baselines/phase83/`；对应回放负测不算新的生产执行。
原有 26 例、完整配置矩阵和最终全链成功仍须在实验主机验收，不能由开发机的跳过项替代。

## 1．更新、构建、回归

每段检查返回状态后再执行下一段。不使用 `set -e`、`exit`、reset 或 clean。
本地源码有修改时先保存；不要强制覆盖。构建产物的既有修改通常可以随分支切换保留。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
REPO="$PWD"
git status --short
git fetch origin phase83-mechanism-execution-closure
git switch --track origin/phase83-mechanism-execution-closure
git rev-parse HEAD
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
mkdir -p "$REPO/experiment/results"
PHASE83_ROOT=$(mktemp -d "$REPO/experiment/results/phase83-XXXXXX")
export PHASE83_ROOT
cmake --build build -j2 > "$PHASE83_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\nPHASE83_ROOT=%s\n' "$BUILD_STATUS" "$PHASE83_ROOT"
tail -n 40 "$PHASE83_ROOT/build.log"
```

已有本地同名分支时，使用 `git switch phase83-mechanism-execution-closure`，
然后 `git pull --ff-only origin phase83-mechanism-execution-closure`。

```bash
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE83_ROOT/regression" \
  --suite "$REPO/experiment/generated-suite"
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
find "$PHASE83_ROOT/regression" -maxdepth 1 -type f -print
```

此处裸套件的 024/029 继续 needs_route 是缺少合同的预期负向基线；不是配置后验收。
检查 `regression.log`、`regression.xml` 和 `generated-suite-strict/batch-evaluation.json`。
023/026 非法输入、016/022 缺特权环境的既有拒绝不应改成通过。

## 2．选择已确认域，直接验证 024 完整路径

本次已选择局部、单线程、私有普通一致性内存域。先阅读随代码提供的机制审查；
只有实际环境满足其中前提时才使用它作为依据。CPU 从当前允许集合中选择并记录，
不把 host CPU 编号当成 guest hart 的架构证明。

```bash
EXPERIMENT_OWNER="phase83-local-experiment"
SYNC_CPU=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
python3 -m riscv2x86_py.prepare_mechanism_selection architecture \
  --privilege-spec riscv-privileged-1.12 --xlen 64 --extensions i zicsr zifencei \
  --output "$PHASE83_ROOT/architecture.json"
python3 -m riscv2x86_py.prepare_mechanism_selection local-sync \
  --owner "$EXPERIMENT_OWNER" --basis "$REPO/docs/local-sync-mechanism-review.md" \
  --cpu "$SYNC_CPU" --domain local-private-single-thread \
  --output "$PHASE83_ROOT/sync-selection.json"
SELECTION_STATUS=$?
printf 'sync_selection_status=%s\n' "$SELECTION_STATUS"
NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'

python3 experiment/run_mechanism_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --output "$PHASE83_ROOT/sync-complete" \
  --architecture-template "$PHASE83_ROOT/architecture.json" \
  --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" \
  --sync-declaration "$PHASE83_ROOT/sync-selection.json" \
  --qemu-source "$REPO/qemu" --qemu-build "$REPO/qemu/build" \
  --native-runner-json "$NATIVE_RUNNER_JSON"
SYNC_STATUS=$?
printf 'sync_complete_status=%s\n' "$SYNC_STATUS"
cat "$PHASE83_ROOT/sync-complete/run-status.json"
```

驱动自动执行准备、批准、消费、绑定、构建、观察及中央审计。无需反复运行架构暂停点。
应同时看到消费 `consumed`、完成路线 `sync`、`productionAcceptanceComplete=true`。
仅 bootstrap 返回 1 不代表故障；最终状态和 blockers 才是验收依据。

## 3．构建独立受控 backend，再验证 029

保留原生 QEMU。已有 backend 只有在来源、manifest、trace header 和实际二进制仍匹配时
才能复用；以下命令构建一个新的隔离环境，不安装覆盖 `/usr/local/bin/qemu-riscv64`。

```bash
python3 -m riscv2x86_py.prepare_controlled_time_backend \
  --qemu-source "$REPO/qemu" --output "$PHASE83_ROOT/controlled-qemu" --jobs 2 \
  > "$PHASE83_ROOT/controlled-build.log" 2>&1
BACKEND_STATUS=$?
printf 'controlled_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 30 "$PHASE83_ROOT/controlled-build.log"
cat "$PHASE83_ROOT/controlled-qemu/build-status.json"
```

仅在构建成功且 `backend.json` 已生成后继续。构建失败查该目录的阶段日志，勿创建占位 manifest。

```bash
python3 -m riscv2x86_py.prepare_mechanism_selection controlled-time \
  --owner "$EXPERIMENT_OWNER" --basis "$REPO/docs/controlled-time-validation-scope.md" \
  --environment shared-external-time-trajectory --output "$PHASE83_ROOT/time-selection.json"
TIME_RUNNER_JSON=$(python3 -c 'import json,os; print(json.dumps([os.path.join(os.environ["PHASE83_ROOT"],"controlled-qemu/build/qemu-riscv64"),"-L","/usr/riscv64-linux-gnu"]))')
python3 experiment/run_mechanism_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --output "$PHASE83_ROOT/time-complete" \
  --architecture-template "$PHASE83_ROOT/architecture.json" \
  --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" \
  --time-mode controlled --time-review "$PHASE83_ROOT/time-selection.json" \
  --time-backend "$PHASE83_ROOT/controlled-qemu/backend.json" \
  --time-runner-json "$TIME_RUNNER_JSON"
TIME_STATUS=$?
printf 'time_complete_status=%s\n' "$TIME_STATUS"
cat "$PHASE83_ROOT/time-complete/run-status.json"
```

成功只归属于 `controlled-time-read-trace` 环境。原生 TIME 严格后端和完整时钟模型继续
未验证；`--time-mode native` 的完整路线仍拒绝。

## 4．组合验收及日志查询

两条单例均完整成功后，将上面两组 source/declaration/backend/runner 参数合并传给
同一个 `run_mechanism_routes.py`，使用全新 output，并添加
`--suite "$REPO/experiment/generated-suite"`。这会执行同一输入清单的裸基线、配置运行、
配置后中央审计和 `suite-preservation.json` 检查。不同环境的 verified 数量必须分别报告。
不要复用已经写入内容的输出目录。

下面都是可执行查询；文件说明文字不作为命令粘贴。

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['PHASE83_ROOT'])
for route in ('sync','time'):
    run=root/(route+'-complete')
    path=run/'run-status.json'
    if not path.is_file(): continue
    status=json.loads(path.read_text())
    print(route, {k:status.get(k) for k in
        ('currentStage','completedRoutes','blockers','productionAcceptanceComplete')})
    for p in run.glob('*-approval-consumption.json'):
        print(p, json.loads(p.read_text()).get('disposition'))
    for p in (run/(route+'-configured')).glob('cases/*/evaluation-result.json'):
        result=json.loads(p.read_text())
        print(p, result['status'], result['reasonCodes'], result.get('targetEnvironment'))
        for attempt in result.get('attempts',[]):
            for layer in (attempt.get('validation') or {}).get('layers',[]):
                print(layer['level'], layer['status'], layer.get('detail','')[:1500])
PY
find "$PHASE83_ROOT" -name '*provider-audit.log' -print -exec cat {} \;
find "$PHASE83_ROOT" -name 'production-acceptance.json' -print -exec cat {} \;
```

若 L0/source DSO/构建失败，保留失败，不关闭 sanitizer、不缩减矩阵、不将后续独立
验证冒充程序 verified。若 L1/L2 失败，查看对应配置运行中的 `work/replay`、
`*-registry.json`、`*-l2-resolved-plan.json` 和 provider invocation 原始观察。
`production-acceptance.json` 只在中央核查的完整路线成功时写入；缺失不能当成成功。

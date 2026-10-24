# Phase95：固定 QEMU 依赖的独立本地准备

本轮基于 Phase94 提交 `41fe335ae81ccf33099d28f6148a133a72964a4b`。修复的是后端准备完整性：主 QEMU 已有五项干净、版本匹配的依赖，但新 worktree 只初始化 Meson，configure 随后访问 GitLab 并因 TLS 失败停止。尚未进入的插件／校准／真实 L3 环节不能据此算通过，也不能据此认定有语义错误。

## 改动与边界

- 新 `l3_qemu_dependencies.py` 从固定提交读取 `.gitmodules` 与五项 gitlink；依赖路径属于已审查的双端 user-mode 构建配置，提交不从本地 HEAD 猜测。
- 主源码也使用独立的本地 clone。它比共享 Git 配置的 worktree 更适合本轮“原目录不变”的要求。源码和子模块均使用 `--no-hardlinks --dissociate`；检查独立 Git 目录、无外部 alternates、对象完整性及实际 checkout 内容。
- donor 路径必须是真正的仓库根目录，要求提交匹配、无已跟踪修改／未跟踪输入。被 assume-unchanged 等索引状态隐藏的修改仍由逐文件 blob/mode 校验拒绝。含空格的上游源码文件名得到支持。
- 独立 checkout 只读取 donor，不修改其配置、工作文件或 refs；消费时不需要 donor 继续留在原路径。准备结果、日志及独立源码目录要保留。
- Git 操作限定 `GIT_ALLOW_PROTOCOL=file`，不自动下载缺失依赖、不改全局 URL、不关闭 TLS 检查。该策略约束 Git 依赖访问，不是整个进程的操作系统网络沙箱。
- 独立核对 gitlink、内容及实际状态后，才生成 `.git-submodule-status`，再运行固定版本 QEMU 的真实 `validate` 脚本。快照本身不是正确性依据。
- configure 固定 `--with-git-submodules=validate --meson=git --enable-tcg`。检查实际 SRC_PATH、Meson 路径、两个 TARGET_DIRS、CONFIG_PLUGIN 和依赖集合。
- 新 backend schema 为 `riscv2x86.qemu-fragment-trace-backend.v2`。生产消费者重新检查准备记录、实际源代码与依赖、配置命令、工具和四项校准。旧 L3 backend v1 不自动升级；受控时间／system 的其他 backend schema 不受此版本变化影响。
- 翻译批准、观察区域、访问比较、缓存模型和中央 closer 的语义要求未放宽。prepare 成功仍保持 `semanticApproval=false`。

本地独立 clone 会占用额外磁盘空间；不借用原对象库以换取空间。缺失依赖时明确失败，未来若支持联网获取应另设显式策略。旧失败目录和 worktree 保留，本轮不做清理或断点覆盖恢复。

## 1. 更新、环境与构建

在 `.venv-l2` 中执行。所有命令失败后保留终端与日志，不使用 `set -e`、`exit`、强制覆盖或清理。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase95-l3-local-dependency-closure
git switch --track origin/phase95-l3-local-dependency-closure
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export PHASE95_ROOT="$(mktemp -d "$REPO/experiment/results/phase95-XXXXXX")"
printf 'PHASE95_ROOT=%s\n' "$PHASE95_ROOT"
cmake --build build -j2 > "$PHASE95_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE95_ROOT/build.log"
```

已存在本地分支时使用 `git switch phase95-l3-local-dependency-closure`。源码修改阻止切换时先保存它们，不使用 reset --hard。要求构建返回码为 0。

## 2. 依赖与相关快速测试

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_qemu_dependencies.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_intent_requirements.py \
  pytools/tests/test_l3_provider_resolution.py \
  pytools/tests/test_execution_environment_closure.py \
  --junitxml="$PHASE95_ROOT/focused.xml" \
  > "$PHASE95_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE95_ROOT/focused.log"
```

要求 0 failures／errors／skips。依赖测试使用真实临时 Git 仓库和固定 QEMU 7.2 的原始 validate 脚本；测试来源 URL 不可访问也应能完成本地准备。它们不冒充真正 QEMU 构建或 guest 执行。

## 3. 在新目录准备后端

原失败目录 `experiment/results/phase94-fU84jC/trace-backend` 继续保留。不要将其改写成成功，也不要复用其中未完成的 manifest。

```bash
python3 -m riscv2x86_py.l3_qemu_backend \
  --qemu-source "$REPO/qemu" \
  --source-sysroot /usr/riscv64-linux-gnu \
  --source-compiler /usr/bin/riscv64-linux-gnu-gcc \
  --target-compiler /usr/bin/gcc \
  --jobs 2 \
  --output "$PHASE95_ROOT/trace-backend" \
  > "$PHASE95_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE95_ROOT/backend.log"
python3 -m json.tool "$PHASE95_ROOT/trace-backend/build-status.json"
```

通过条件：返回 0、`complete=true`、`currentStage=complete`，并生成 backend v2。仍需四项真实校准，而不是只完成依赖。

下面检查准备记录、实际配置和校准概要：

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['PHASE95_ROOT']) / 'trace-backend'
path = root / 'backend.json'
if path.is_file():
    backend = json.loads(path.read_text())
    print('schema:', backend['schemaVersion'])
    print('backendIdentity:', backend['backendIdentity'])
    binding = backend['sourcePreparation']
    record = json.loads(Path(binding['recordPath']).read_text())
    print('preparationIdentity:', record['preparationIdentity'])
    for item in record['dependencies']:
        print('DEPENDENCY:', item['path'], item['commit'], item['preparedSnapshot'])
    print('configuration:', json.dumps(binding['configuration'], ensure_ascii=False))
    for item in backend['calibration']:
        print('CALIBRATION:', item['side'], item['access'], item['status'])
else:
    print('Backend 尚未完成。查看 build-status.json 与当前阶段的命令记录。')
PY
```

准备阶段包括 dependency_discovery、dependency_validation、source_checkout、dependency_materialization、dependency_snapshot，随后为 configure、configuration_validation、compile、plugin、calibration、final_validation。失败的 `failureDetail` 会指出模块路径、要求与实际状态。日志位置：

```bash
find "$PHASE95_ROOT/trace-backend" -type f \
  \( -name '*.command.json' -o -name 'source-preparation.json' -o -name 'build-status.json' \) \
  -not -path '*/source/*' -print
```

依赖命令在 `dependency-preparation/`；configure／make 在 `build/`；校准在 `calibration/<side>/<access>/`。缺失对象或版本错误应在依赖阶段停止，且不产生正式 backend.json。不能手工删除校验字段后继续。

## 4. 真实 L3 逻辑轨迹

只在第 3 步完整成功后执行。

```bash
export RV2X86_L3_TRACE_BACKEND="$PHASE95_ROOT/trace-backend/backend.json"
python3 experiment/run_l3_memory_trace.py \
  --input "$REPO/experiment/generated-suite/case_001_61fc75fd49.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE95_ROOT/read-trace" \
  > "$PHASE95_ROOT/read-trace.log" 2>&1
TRACE_STATUS=$?
printf 'trace_status=%s\n' "$TRACE_STATUS"
tail -n 80 "$PHASE95_ROOT/read-trace.log"
python3 -m json.tool "$PHASE95_ROOT/read-trace/run-status.json"
```

要求返回 0、productionAcceptanceComplete=true，以及实际 evaluation 中 L0/L1/L2/L3 均 verified。

## 5. 显式缓存模型与生产负测

```bash
python3 -m riscv2x86_py.l3_cache_model \
  --output "$PHASE95_ROOT/cache-model.json" \
  --line-bytes 64 --set-count 16 --ways 4
MODEL_STATUS=$?
printf 'model_status=%s\n' "$MODEL_STATUS"
```

模型创建返回 0 后执行：

```bash
python3 experiment/run_l3_memory_trace.py \
  --input "$REPO/experiment/generated-suite/case_001_61fc75fd49.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TRACE_BACKEND" \
  --cache-model "$PHASE95_ROOT/cache-model.json" \
  --output "$PHASE95_ROOT/read-cache-model" \
  > "$PHASE95_ROOT/read-cache-model.log" 2>&1
CACHE_STATUS=$?
printf 'cache_status=%s\n' "$CACHE_STATUS"
python3 -m json.tool "$PHASE95_ROOT/read-cache-model/run-status.json"
```

要求 access_pattern 与 cache_model 均闭合。两条路线成功后：

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE95_ROOT/production.xml" \
  > "$PHASE95_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE95_ROOT/production.log"
```

要求 **2 passed、0 skipped**。它们使用重命名输入跑正常生产入口，并在验收后主动篡改临时轨迹，确认中央审计拒绝。不要把被篡改的临时测试目录重新当作正向证据；独立 read-trace／read-cache-model 目录不受影响。

## 6. 提取层级结果

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['PHASE95_ROOT'])
for name in ('read-trace', 'read-cache-model'):
    paths = sorted((root/name/'batch/cases').rglob('evaluation-result.json'))
    print('\nEXPERIMENT:', name, 'reportCount:', len(paths))
    for path in paths:
        value = json.loads(path.read_text())
        print('REPORT:', path)
        print('status:', value.get('status'), 'reasons:', value.get('reasonCodes'))
        for attempt in value.get('attempts', []):
            print('translationOutcome:', attempt.get('translationOutcome'))
            for layer in (attempt.get('validation') or {}).get('layers', []):
                print('LAYER:', layer.get('level'), layer.get('status'))
                if layer.get('level') == 'L3':
                    print(layer.get('detail'))
PY
```

上游准入失败、构建失败、异常、超时、缺失 footer、错误轨迹、错误模型或陈旧身份都不能转成 verified。

## 7. 兼容性与最终回归

新 L3 原始输入与合法变化链通过后，重新执行此前 016／022／024／029 的组合流程，使用当前代码生成的新观察器绑定，不直接拷贝旧批准报告。它检查旧能力未退化，不授予这些操作本次普通单读 L3 许可。

保持上一轮无跳过回归所需的真实配置，并增加本次 RV2X86_L3_TRACE_BACKEND。先核对配置：

```bash
python3 - <<'PY'
import os
from pathlib import Path
for name in ('RV2X86_L3_TRACE_BACKEND', 'RV2X86_CONTROLLED_SYSTEM_BACKEND',
             'RV2X86_CONTROLLED_QEMU_MANIFEST', 'RV2X86_LOCAL_SYNC_DECLARATION'):
    value = os.environ.get(name, '')
    print(name, value, 'file_exists=', bool(value) and Path(value).is_file())
for name in ('RV2X86_CONTROLLED_QEMU_RUNNER_JSON', 'RV2X86_QEMU_SOURCE',
             'RV2X86_QEMU_BUILD', 'RV2X86_NATIVE_RUNNER_JSON'):
    print(name, os.environ.get(name, 'MISSING'))
PY
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 "$CLANG10" \
  --output "$PHASE95_ROOT/regression-final" \
  --require-no-regression-skips \
  > "$PHASE95_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 40 "$PHASE95_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE95_ROOT/regression-final/run-status.json"
```

要求 failures/errors/skipped 均为 0。开发环境无真实 RISC-V 工具链时的跳过不算生产验收。本次仍是普通单次读取、编译器 asm 区域和声明的对象相对缓存模型；没有物理缓存、时序、推测执行或全部 32 项 L3 完成的结论。

## 开发环境验证记录

新增 34 项依赖／配置／生命周期检查全部通过；包含真实临时 Git 仓库、源对象库 alternates 解耦、donor 移动后的独立性、隐藏文件修改，以及固定 QEMU 7.2 原始脚本的 validate 协议。选定回归为 **1480 passed、45 skipped**。跳过项涉及开发环境缺少真实前端工具链或显式生产 backend，不能作为生产通过证据。实际双端 QEMU 构建、四项校准、原始输入 L3 生产以及最终无跳过回归，仍须由以上主机步骤完成。

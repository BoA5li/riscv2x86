# Phase 94：真实 L3 访存轨迹与显式缓存模型

本轮加入一条正常生产入口，而不是预制通过报告：前端和编译器片段绑定 → 既有架构证明与候选物化 → L0/L1/L2 → 获批意图生产与消费 → 可执行部署合同 → 双端实际 QEMU 插件采集 → 属性比较 → 中央重闭合 → 独立生产验收。

## 支持范围与结论

首期注册机制只接受具有完整编译器范围和架构批准的普通单次读取：单函数、单 asm、一个指针参数、整数返回、私有有效普通内存对象。选择依据是 proof facts、对象与 operand 绑定、批准关系和 compiler scope；不存在案例编号、函数名或助记符匹配。

| 属性 | 证据 | 不声称的范围 |
| --- | --- | --- |
| `memory.fragment-access` / `access_pattern` | 两端真实 TCG 成功访存回调，区域进出、读取次数、宽度、对象相对偏移和顺序 | 整个函数、loader、libc、包装程序的全部访存 |
| `cache.fragment-stream-model` / `cache_model`，显式启用 | 上述实际轨迹进入声明几何参数、空初态、对象相对地址与 LRU 规则的模型，独立重放 | 物理缓存、真实命中率、时延、预取、推测执行、其他代码的缓存污染 |

两者都是指定输入域和有限执行下的实验结论，不替代架构证明，也不是全部微架构语义的通用证明。未提供 RISC-V 真机不妨碍这条 TCG／模型路线；不能据此发布物理硬件等价结论。

动态执行只采集编译器 `#APP` 至 `#NO_APP` 区域。标签本身不生成指令，重编译 object 与最终 executable 的整个函数机器码必须分别等于实际源 `.o` 和目标 `.so` 的函数机器码；不一致即拒绝。中央审计重新运行编译器以验证区域归因，并独立重链接、比较可加载执行镜像的代码与数据。部署链接关闭 build ID；不把非加载的 FILE 符号和 section-table 定位元数据当作执行语义，避免旧式整文件重建误拒绝。不能把 `.o` 或 `.so` 当作可启动程序。

源／目标 L0–L2 的原执行环境单独保留；新增 TCG 执行程序与原语义产物通过部署记录绑定，报告明确记录两套身份。没有把目标本地 L2 执行改称为 QEMU 执行。

## 关键实现

- `runtime/l3_qemu_trace.c`：QEMU 7.2 plugin API v1；成功 guest 访存、进出事件和完整 footer；不读取 API v1 不支持的寄存器／内存值。
- `l3_qemu_backend.py`：独立、固定 QEMU 7.2 上游提交的双 ISA 后端；四个真实读／写校准；工具、编译器子工具和产物绑定。保留已安装 QEMU。
- `l3_memory_intent.py`：普通架构证明消费者；生产入口绑定真实 fragment 和 effect relation，不从名称推断属性。
- `l3_trace_deployment.py`：获批替代代码、原产物、零指令区域和实际执行程序绑定；独立重算区域。
- `l3_qemu_memory_route.py`：实际采集、归一化、失败判定、provider registry、中央 closer 和原始文件重放。
- `l3_cache_model.py`：版本化的显式模型；新增 `cache_model` 属性使用 v2 intent／requirements，旧版本不能暗中承载新属性。
- 普通 `automatic_batch_cli` 增加 `--l3-memory-backend`、`--l3-cache-model`，复用 `--require-l3`；`experiment/run_l3_memory_trace.py` 加入逐阶段持久状态和独立审计。

同时修正已有 `approved_replacement` 的版本协议：生产端 `phase6-approval-v1`、v2 和 functional fallback v1 使用 FNV-1a；CSR runtime 的独立 SHA 协议保持不变。版本、候选归属和文本摘要仍全部校验。

## 1. 更新和创建实验目录

以下块只含可执行命令；在 Bash 中逐块运行。使用 `set +e`，不关闭失败后的终端。失败后保留目录，修复输入后使用新的输出目录，不能覆盖旧证据。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase94-l3-qemu-trace-cache-model
git switch --track origin/phase94-l3-qemu-trace-cache-model
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export PHASE94_ROOT="$(mktemp -d "$REPO/experiment/results/phase94-XXXXXX")"
printf 'PHASE94_ROOT=%s\n' "$PHASE94_ROOT"
cmake --build build -j2 > "$PHASE94_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE94_ROOT/build.log"
```

若分支已存在，使用 `git switch phase94-l3-qemu-trace-cache-model`。本地有源码修改导致切换受阻时先保存它们，不使用强制覆盖或 `reset --hard`。既有生成的 build／pycache 修改不是本次提交内容。

## 2. 快速回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_intent_requirements.py \
  pytools/tests/test_l3_provider_resolution.py \
  pytools/tests/test_execution_environment_closure.py \
  --junitxml="$PHASE94_ROOT/focused.xml" \
  > "$PHASE94_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 60 "$PHASE94_ROOT/focused.log"
```

这一步验证协议、负测、模型、原生 GCC 区域标签和旧链兼容性；不是实际双端 L3 生产通过。

## 3. 准备独立双端观察后端

此前 `/usr/bin/qemu-x86_64` 版本不足，因此单独构建 API v1 兼容的两个 user executors。不修改 `/usr/local/bin/qemu-riscv64`，也不使用旧 controlled-time 补丁冒充普通访存机制。

```bash
python3 -m riscv2x86_py.l3_qemu_backend \
  --qemu-source "$REPO/qemu" \
  --source-sysroot /usr/riscv64-linux-gnu \
  --source-compiler /usr/bin/riscv64-linux-gnu-gcc \
  --target-compiler /usr/bin/gcc \
  --jobs 2 \
  --output "$PHASE94_ROOT/trace-backend" \
  > "$PHASE94_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 60 "$PHASE94_ROOT/backend.log"
python3 -m json.tool "$PHASE94_ROOT/trace-backend/build-status.json"
```

必须是该目录的 `build-status.json.complete=true`，且生成 `backend.json` 后再继续。构建检查固定上游提交 `b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56`。四个校准是 source／target × read／write，直接检查真实 guest 指令回调、符号地址、宽度和方向；只生成文件或者 `semanticApproval=false` 都不是翻译批准。

构建失败查看该目录及 `build` 子目录中的 `*.command.json`；记录包括具体命令、返回码、stderr 和超时。不要手工删除不支持的编译参数后把旧 manifest 标记为通过。

## 4. 首个原始输入：实际逻辑轨迹

```bash
export RV2X86_L3_TRACE_BACKEND="$PHASE94_ROOT/trace-backend/backend.json"
python3 experiment/run_l3_memory_trace.py \
  --input "$REPO/experiment/generated-suite/case_001_61fc75fd49.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE94_ROOT/read-trace" \
  > "$PHASE94_ROOT/read-trace.log" 2>&1
TRACE_STATUS=$?
printf 'trace_status=%s\n' "$TRACE_STATUS"
tail -n 60 "$PHASE94_ROOT/read-trace.log"
python3 -m json.tool "$PHASE94_ROOT/read-trace/run-status.json"
```

通过条件：驱动返回 0；`productionAcceptanceComplete=true`；对应 evaluation 中 L0／L1／L2／L3 全部 `verified`；原始进出和访存记录存在；每端四次实际调用及各自的一个获批读取；独立 acceptance 成功。若失败，先定位 `currentStage` 和 `blockers`，不继续将裸基线通过数作为 L3 成功数。

## 5. 相同真实输入：显式缓存模型

```bash
python3 -m riscv2x86_py.l3_cache_model \
  --output "$PHASE94_ROOT/cache-model.json" \
  --line-bytes 64 --set-count 16 --ways 4
MODEL_STATUS=$?
printf 'model_status=%s\n' "$MODEL_STATUS"
python3 experiment/run_l3_memory_trace.py \
  --input "$REPO/experiment/generated-suite/case_001_61fc75fd49.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TRACE_BACKEND" \
  --cache-model "$PHASE94_ROOT/cache-model.json" \
  --output "$PHASE94_ROOT/read-cache-model" \
  > "$PHASE94_ROOT/read-cache-model.log" 2>&1
CACHE_STATUS=$?
printf 'cache_status=%s\n' "$CACHE_STATUS"
python3 -m json.tool "$PHASE94_ROOT/read-cache-model/run-status.json"
```

必须同时完成 access_pattern 与 cache_model 两个属性。模型是从空初态开始处理连续的四次片段调用，不包含其他代码事件。模型结果成功不能将 `physicalMicroarchitectureClaimed` 改为 true。

## 6. 合法重命名和证据篡改验收

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE94_ROOT/production.xml" \
  > "$PHASE94_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE94_ROOT/production.log"
```

必须 **2 passed、0 skipped**。两项均通过真实前端和正常批处理入口，不构造批准来替代生产。每项成功后会在临时测试目录内主动篡改源 raw trace，要求独立审计拒绝；该临时目录中事后被篡改的证据不能再作为正向发布材料。第 4／5 步的独立目录不受影响。

## 7. 查询原始日志和逐维结果

```bash
find "$PHASE94_ROOT/read-trace" "$PHASE94_ROOT/read-cache-model" \
  -type f \( -name 'evaluation-result.json' -o -name 'experiment-contract.json' \
  -o -name 'provider-registry.json' -o -name 'deployment.json' \
  -o -name 'guest-trace.log' -o -name 'observation-result.json' \
  -o -name 'l3-production-acceptance.json' \) -print
```

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['PHASE94_ROOT'])
for name in ('read-trace', 'read-cache-model'):
    for path in sorted((root/name/'batch/cases').rglob('evaluation-result.json')):
        data = json.loads(path.read_text())
        print('\nREPORT:', path)
        print('status:', data.get('status'), 'reasons:', data.get('reasonCodes'))
        for attempt in data.get('attempts', []):
            for layer in (attempt.get('validation') or {}).get('layers', []):
                print('LAYER:', layer.get('level'), layer.get('status'))
                if layer.get('level') == 'L3':
                    detail = layer.get('detail')
                    if isinstance(detail, str):
                        try:
                            detail = json.loads(detail)
                        except ValueError:
                            pass
                    print(json.dumps(detail, ensure_ascii=False, indent=2))
PY
```

`providerDetail` 包含实际 executor、runnerArguments、产物部署、rawTracePath、归一化事件、模型结果和逐属性结论。若上层 L3 失败，优先查看 reasonCodes；若 trace 未生成，查看部署和 execute.command.json；没有 footer、异常、超时、次数错误、偏移／宽度／方向错误、失效身份均不能 verified。

## 8. 兼容回归、32 项覆盖率和后续扩展

首条新 L3 正向路线通过后，先按上一轮成功配置重新运行 016／022／024／029 组合验收；它验证旧支持域不退化，不授予这些操作普通单读 L3 许可。原有控制时间、同步、system 的观察器或批准失效时要用当前代码重新准备，不要把旧报告直接复制为新报告。

普通 32 项裸基线仍可用来核查既有 L0–L2 状态，不要求其全部变成 L3 verified。若把新单读机制直接选择给整个 32 项输入集，非普通单读的输入会拒绝该路线，整体不能通过 `--require-l3`；这是明确的覆盖边界，不应删除该门槛。

最终选定回归已经加入新 trace 和生产测试。保持上一轮无跳过回归所需的环境变量，并增加 `RV2X86_L3_TRACE_BACKEND`。先核对所选 manifest 确实存在：

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
  --output "$PHASE94_ROOT/regression-final" \
  --require-no-regression-skips \
  > "$PHASE94_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 40 "$PHASE94_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE94_ROOT/regression-final/run-status.json"
```

未配置显式后端导致生产测试 skipped，不等于真实链验证完成。最终目标是回归 failures／errors／skipped 均为 0，以及本轮独立 L3 生产 acceptance 完整；不能单看 pytest passed 总数。

后续按独立机制扩展普通写／多对象、分支轨迹、同步发布、时序统计、推测和物理缓存路线。每条都需新的适用合同、实际观察器、失败语义及中央重放；本次不把“缺少机制”改成 not_applicable。

## 开发环境验证记录

新增协议／模型／原生编译器测试 47 项通过；插件已针对官方 QEMU 7.2 API v1 头文件在 `-Wall -Wextra -Werror` 下成功编译。开发环境没有真实 RISC-V GCC／QEMU／Clang 前端工具链，双端生产、32 项真实实验和最终无跳过回归尚待上述主机步骤验收。日志中的跳过不能被当作生产成功。

选定回归：1446 passed、45 skipped；跳过原因是本环境缺少真实工具链或显式生产 backend。最后的 inventory 环境归属调整另经相关 86 项测试通过。不能据此声称无跳过回归或真实 QEMU 生产已通过。

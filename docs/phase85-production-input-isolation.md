# Phase 85：合法变化生产测试的输入／输出隔离

基线：`502afb9d7c157470293b6d21e50e1c1a6fe7d649`。
分支：`phase85-production-input-isolation`。

## 核实与修复

两项真实重命名测试原来把源码放在 `tmp_path`，输出放在其子目录
`tmp_path/production`。单文件 automatic batch 使用源码父目录作为 source root；
评估 work 位于输出内，因而与 source root 重叠。评估器在创建 work 和启动 frontend
前正确拒绝；batch 将该异常写入 evaluation-result.json，驱动却只报告缺少翻译报告。
因此没有 frontend.stderr 或 preflight 文件符合该失败位置，不能据此认定前端未支持重命名。

测试现在使用 `tmp_path/inputs/renamed_*.c` 和兄弟目录 `tmp_path/production`。
保留真实工具、原始语义、函数重命名、中央审计与全部验收断言；不替换输入或合同。
驱动按实际 source root 提前拒绝输出重叠，解析符号链接；缺报告时保留底层
case 状态、reasonCodes、detail、orchestrationFailure 到 run-status.json.failureDiagnostics。
读取诊断 resultPath 时拒绝跳出 batch 目录；多个报告单独报告歧义。
评估器隔离规则、翻译批准、合同消费、CSR 语义与 L2 closer 均未放宽。

该修复消除已确认的启动阻塞；尚不能据此保证之后所有真实阶段都通过。
开发主机的验证范围与缺工具情况记录在 experiment/baselines/phase85/validation-summary.json。
024 仍限定局部单线程私有普通一致性内存；029 仍为受控读取轨迹及结果流。
原生严格 TIME、完整时钟、跨 hart 发布、L3 不在本轮完成声明内。

## 1．更新并选择实验环境

逐段执行并检查退出状态。不使用 set -e、exit、reset 或 clean；本地修改先自行保存。
没有修改 C++ 或 runtime，本次无需因本补丁重新构建已成功的 frontend／backend。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
git status --short
git fetch origin phase85-production-input-isolation
git switch --track origin/phase85-production-input-isolation
git rev-parse HEAD

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PREVIOUS_ROOT="$REPO/experiment/results/phase83-production-ToHPRs"
export PHASE85_ROOT="$(mktemp -d "$REPO/experiment/results/phase85-XXXXXX")"
printf 'PHASE85_ROOT=%s\n' "$PHASE85_ROOT"

export RV2X86_LOCAL_SYNC_DECLARATION="$PREVIOUS_ROOT/sync-selection.json"
export RV2X86_QEMU_SOURCE="$REPO/qemu"
export RV2X86_QEMU_BUILD="$REPO/qemu/build"
export RV2X86_NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
export RV2X86_CONTROLLED_QEMU_MANIFEST="$PREVIOUS_ROOT/controlled-qemu/backend.json"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON="$(python3 -c 'import json,os; print(json.dumps([os.path.join(os.environ["PREVIOUS_ROOT"],"controlled-qemu/build/qemu-riscv64"),"-L","/usr/riscv64-linux-gnu"]))')"
```

本地分支已存在时改用 `git switch phase85-production-input-isolation`，再
`git pull --ff-only origin phase85-production-input-isolation`。
复用环境声明和 backend 的前提是其机制、CPU 约束与二进制身份仍成立；如有变化应重新准备。
测试重新生成源码和 fragment 绑定、批准和 provider，不复用旧批准。

## 2．先重跑本次失败的两个真实生产测试

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_local_sync_production.py \
  pytools/tests/test_controlled_time_production.py \
  --junitxml="$PHASE85_ROOT/production.xml" \
  > "$PHASE85_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 70 "$PHASE85_ROOT/production.log"
```

必须 2 passed、0 skipped、状态 0 才继续。跳过表示缺工具或未选择环境，不能算通过。
失败则保留 pytest 给出的目录，读取 production/run-status.json 的 currentStage、
blockers、failureDiagnostics，以及对应阶段的 batch-evaluation.json 和 evaluation-result.json。
目录隔离修复后若出现后续阶段错误，应依原始证据定位，不能改写为成功。

## 3．最终无跳过回归

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE85_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE85_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 30 "$PHASE85_ROOT/regression-driver.log"
tail -n 20 "$PHASE85_ROOT/regression-final/regression.log"
cat "$PHASE85_ROOT/regression-final/run-status.json"
```

验收要求：状态 0、无失败和跳过。不能只看到 pytest 结束就认为整条验收通过。
本次增加 9 项测试；与原 1014 项选择范围相同的环境中应收集到 1023 项。
若需对新提交重建原始输入组合验收，使用 docs/phase84-csr-access-coverage.md 第 3 节
原命令，将所有 PHASE84_ROOT 换为 PHASE85_ROOT（输出为新目录 combined）。
仍要求两条路线 L0/L1/L2、中央审计和原 26 例保持性通过，不把受控 TIME 计为原生严格等价。

## 4．提取失败／跳过原因

以下是完整可执行命令，不把日志字段说明当成 shell 命令粘贴。

```bash
python3 - <<'PY'
import os
from pathlib import Path
import xml.etree.ElementTree as ET
root = Path(os.environ['PHASE85_ROOT'])
for path in (root/'production.xml', root/'regression-final/regression.xml'):
    if not path.is_file():
        print('文件不存在:', path)
        continue
    print('\nXML:', path)
    for case in ET.parse(path).getroot().iter('testcase'):
        for kind in ('failure', 'error', 'skipped'):
            node = case.find(kind)
            if node is not None:
                print(kind, case.get('classname'), case.get('name'))
                print(node.get('message', ''))
                print(node.text or '')
PY
```

新诊断保留底层异常，不自动授予翻译许可，也不把 inconclusive 或 partial 改成 verified。

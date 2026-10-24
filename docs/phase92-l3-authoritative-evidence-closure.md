# Phase92：L3权威需求与证据消费闭合

基线：Phase91，a64e62cca17accd75361aec32cf43d32621d4c40。
分支：phase92-l3-authoritative-evidence-closure。

## 修改目标与证据边界

本轮修复评估逻辑：结果不能删除原始必需属性后重算摘要取得verified；多个program组不能因遍历顺序覆盖失败或未完成；覆盖率和论文统计消费正式dimension schema；自定义注册provider也要满足独立L0/L1/L2和实际产物绑定。

这不是自动为全部输入授予微架构意图，也没有增加一个冒充硬件的通用测量后端。
此前1270项无跳过回归及30例组合成功属于Phase91基线。本轮需重新验证；L3 not_run不能改成verified来提高覆盖率。

## 具体修订

- l3_evidence_closure新增validate_fragment_against_requirement：保留自洽性解析，随后对原始权威需求重新close，逐项检查property/dimension/unit/fragment/program/profile/requirement及提供的执行上下文。
- provider验收核对双端报告正文、合同和实际产物身份、翻译产物、独立L0/L1/L2证据及scope；摘要不是语义授权。
- 批次和论文消费同一个重闭合入口。旧的自报缩减属性结果即使重新计算内容摘要也不能形成正式成功。
- partial结果保留完整requiredProperties；已存在且有效的反例不被缺失的其他属性隐藏。没有反例但证据缺失仍为inconclusive。
- 状态聚合与顺序无关；混合已运行和未运行、混合正式与诊断scope不形成正式verified。论文中的not_run不再被默认升级。
- 批次L3重新审计降级时，案例汇总同步降级并记录l3.summary.authoritative-evidence-not-verified；原始执行报告保留，便于追查。
- 覆盖率和论文统计使用正式comparisonEvidenceIdentity及闭合结果，不读取不存在的dimension.evidenceIdentity；provider调用按(providerId,executionIdentity)去重。
- manifest校验增加属性唯一性、dimension/unit类型、状态/意图/disposition组合及重复fragment检查。
- 默认回归驱动增加全部L3专项、新反例和论文统计测试，避免再次出现“全套选定回归未含L3”的误解。

现有L3 v1 dimension/fragment记录未增加伪造字段。旧的完整、适用记录可按权威需求重验；只有自洽性而没有权威需求的离线结果不能计入正式成功。

## property与比较器绑定

v2–v6实验合同继续保留原有语义：每个dimension最多一个全合同义务。不能通过在同一dimension添加多个不同property名字，就无依据地取得多个谓词的证明。

新增显式v7实验合同。它保留v2–v6中一种合同的完整字段，schemaVersion改为：

```text
riscv2x86.microarchitecture-experiment-contract.v7
```

增加baseSchemaVersion和propertyBindings。例如原始权威需求中的一项完整访存合同义务：

```json
{
  "baseSchemaVersion": "riscv2x86.microarchitecture-experiment-contract.v2",
  "propertyBindings": [
    {
      "propertyId": "property:access",
      "dimension": "access_pattern",
      "unit": "fragment",
      "comparatorId": "logical-access-contract.v1",
      "obligationIds": ["access:0"]
    }
  ]
}
```

这只是新增字段示例，不是独立有效合同或许可。必须同时满足既有profile、proof、relation、环境、产物及provider检查。

已注册的比较器：logical-access-contract.v1、logical-control-contract.v1、synchronization-contract.v1、platform-statistical-contract.v1、registered-platform-experiment.v1。
obligationIds必须精确覆盖对应比较器的全部eventId、同步条件或metricId；当前版本不支持通过选择子集减弱义务。不同property可显式指向同一完整比较，但不能因此声称检查了一个未实现的新谓词。

v7 provider必须在contractSchemas中显式选择v7；不会静默升级旧配置或自动获得新的实验授权。

## 验证范围

新增负测覆盖删除属性并重算摘要、dimension/unit替换、错误上下文/报告、partial和有效反例、多个program组的两种顺序、manifest不一致、显式比较器选择子集、重复provider调用。

真实子进程协议测试经过现有runner→registry→闭合→覆盖率→论文层消费；源/目标观察为明确合成数据，L0/L1/L2为显式fixture。这验证协议及消费正确性，不证明实际RISC-V/x86硬件性质，也不替代frontend和真实平台生产验收。

## 1. 更新并保存实验目录

在已有.venv-l2终端执行，不使用set -e或shell exit，不删除旧结果：

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase92-l3-authoritative-evidence-closure
git switch --track origin/phase92-l3-authoritative-evidence-closure
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export PHASE92_ROOT="$(mktemp -d "$REPO/experiment/results/phase92-XXXXXX")"
printf 'PHASE92_ROOT=%s\n' "$PHASE92_ROOT"
cmake --build build -j2 > "$PHASE92_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 25 "$PHASE92_ROOT/build.log"
```

已有本地分支时使用git switch phase92-l3-authoritative-evidence-closure。
不要重置用户构建文件或批量清理工作区。返回非0先看对应日志。

## 2. L3专项及报告回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_*.py \
  pytools/tests/test_paper_evaluation.py \
  pytools/tests/test_batch_evaluation_cli.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_validation_configuration.py \
  pytools/tests/test_translation_validation.py \
  --junitxml="$PHASE92_ROOT/l3.xml" \
  > "$PHASE92_ROOT/l3.log" 2>&1
L3_STATUS=$?
printf 'l3_test_status=%s\n' "$L3_STATUS"
tail -n 60 "$PHASE92_ROOT/l3.log"
```

要求零失败。这里的通过是模块与协议测试通过，不能写作真实硬件L3通过。

## 3. 保持Phase91真实生产与组合路线不退化

本轮不修改SYSTEM、TIME或visibility观察器及构建recipe。先校验已有SYSTEM backend，复用Phase91刚重新准备成功的024/029配置，不使用失效Phase84 provider。

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$REPO/experiment/results/phase90-M3h0OX/controlled-system/backend.json"
export COMBINED_2429="$REPO/experiment/results/phase91-lXLcwr/routes-2429-current-r2"
python3 - <<'PY'
import os
from riscv2x86_py.controlled_system_backend import validate_backend
print(validate_backend(os.environ['RV2X86_CONTROLLED_SYSTEM_BACKEND'])['backendIdentity'])
PY
```

若实际环境或工具身份改变，应重新准备适用配置，不能修改hash绕过。backend校验通过后：

```bash
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --suite "$REPO/experiment/generated-suite" \
  --existing-provider-directory "$COMBINED_2429/contracts/providers" \
  --csr-architecture-directory "$COMBINED_2429/contracts/architecture" \
  --csr-environment-contract-directory "$COMBINED_2429/contracts/csr" \
  --instruction-stream-sync-directory "$COMBINED_2429/contracts/sync" \
  --output "$PHASE92_ROOT/combined" \
  > "$PHASE92_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 50 "$PHASE92_ROOT/combined-driver.log"
if [ -f "$PHASE92_ROOT/combined/run-status.json" ]; then
  python3 -m json.tool "$PHASE92_ROOT/combined/run-status.json"
fi
if [ -f "$PHASE92_ROOT/combined/suite-preservation.json" ]; then
  python3 -m json.tool "$PHASE92_ROOT/combined/suite-preservation.json"
fi
```

要求生产及中央审计完成、无阻塞、26例不退化、四条配置路线verified。当前固定32例目标为30 verified，其余023/026保留非法输入拒绝。这一步仍不配置L3，不应期望其L3变为verified。

## 4. 最终选定范围无跳过回归

保持此前成功的工具搜索环境，不重复追加PATH前缀。真实测试配置显式选择：

```bash
export PREVIOUS_ROOT="$REPO/experiment/results/phase83-production-ToHPRs"
export RV2X86_LOCAL_SYNC_DECLARATION="$PREVIOUS_ROOT/sync-selection.json"
export RV2X86_QEMU_SOURCE="$REPO/qemu"
export RV2X86_QEMU_BUILD="$REPO/qemu/build"
export RV2X86_NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
export RV2X86_CONTROLLED_QEMU_MANIFEST="$PREVIOUS_ROOT/controlled-qemu/backend.json"
RV2X86_CONTROLLED_QEMU_RUNNER_JSON="$(python3 - <<'PY'
import json, os
from pathlib import Path
binary = Path(os.environ['PREVIOUS_ROOT']) / 'controlled-qemu/build/qemu-riscv64'
print(json.dumps([str(binary), '-L', '/usr/riscv64-linux-gnu']))
PY
)"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE92_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE92_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 30 "$PHASE92_ROOT/regression-driver.log"
if [ -f "$PHASE92_ROOT/regression-final/regression.log" ]; then
  tail -n 25 "$PHASE92_ROOT/regression-final/regression.log"
fi
if [ -f "$PHASE92_ROOT/regression-final/run-status.json" ]; then
  python3 -m json.tool "$PHASE92_ROOT/regression-final/run-status.json"
fi
```

要求failures/errors/skipped均0、blockers为空。未传--suite，因此generatedSuiteExecuted=false正常；本轮回归已经包含L3专项，但仍不等于硬件L3生产验收。

## 5. 真正的L3平台验收前提

现有32例不能根据指令名字自动获得微架构意图。生产正向路线仍须提供：

1. frontend/translation-proof产生并绑定真实fragment的完整l3IntentProfile；不能由实验脚本自报verified或只填写hash。
2. 获批目标关系、必需property和观察边界；每项绑定实际可执行比较器。
3. 实际源/目标平台、编译产物、runner身份、环境与采样/校准协议。
4. 真实runner输出及原始聚合样本；必须和实际产物、读取/访存/控制事件相对应。
5. L0/L1/L2前置通过；L3 provider适用并执行；所有属性在中央闭合后计数。

通用批处理接入点仍为--l3-provider-directory。未经这些前提的输入继续保持inconclusive/not_run/needs_route。SYSTEM路线与L3的显式互斥保护保持；本轮没有宣称完成受控SYSTEM微架构实验。

普通QEMU不能自动代表真实RISC-V缓存/预测器/周期行为。如果使用特定模拟模型，应限定结论为该模型。真实硬件验证需要明确待评估性质和可用的源/目标平台，当前仓库没有自动生成这些事实的通用后端；本轮不伪造这一能力。

## 开发环境验证结果

本轮L3及相关消费测试209 passed；其余选定回归1216 passed、43 skipped，总计1425 passed、43 skipped、零失败。Phase91原有1270项测试逐项结果不变。43项跳过为2项未选择真实SYSTEM backend、40项缺少真实生产工具链、1项缺少源ISA工具。

开发环境缺少真实Clang/交叉GCC/QEMU；宿主机步骤3、4和未来平台实验不能由合成协议测试替代。此次验证是默认回归集合加相关配置/翻译/批处理测试，不宣称整个仓库所有测试或真实硬件L3已完成。

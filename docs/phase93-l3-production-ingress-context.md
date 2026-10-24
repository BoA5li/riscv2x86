# Phase93：L3 生产接入、实际产物绑定与强制验收

## 交付范围与尚未完成的目标

本轮基于 Phase92 `b077c05380afa94aa234f8fe2300d1026dd6139e`。

修复了实际代码中的三个生产缺口：

1. `Finding` 原来没有 L3 意图字段，报告经过 `load_report/save_report` 后会丢失它们。现在显式保存并校验 `l3IntentProfile`，保留独立的消费记录 `l3IntentReceipt`。
2. 自动翻译入口原来没有意图生产器调用步骤。现在可以显式选择经审查的外部语义生产器，在真实翻译批准和编译器片段闭合后生成实验义务。生产器必须覆盖所有获批候选，并绑定实际 proof 与获批 effect-relation set；不从案例编号、指令字符串或 L2 分类推断实验目标或 `none`。
3. L3 观察器原来的 stdin 没有实际构建产物。现在自动评估器传入类型化执行上下文，观察器得到本次程序路径、内容摘要、build identity 和独立 invocation identity；回包必须绑定同一次执行，前后复核实际文件。中央 provider 再检查一次，执行绑定进入证据身份。

新增 `--require-l3` 和独立生产验收工具，使 L0–L2 成功、单元测试成功、未运行 L3 都不能满足指定的 L3 生产验收目标。

**这不等于 32 例已完成真实 L3 验证。** 当前仓库仍没有本轮平台上已审查、可直接执行的通用 L3 意图生产器与物理观察器组合。新增入口是外部语义工具的显式信任边界，不是内置的全指令语义证明器。`reviewBasis`、工具摘要、消费记录均不构成语义证明；消费时会重新执行选定生产器，对当前编译器绑定和批准输入重放，拒绝仅重新计算 JSON 哈希的篡改。

当前保留的边界：

- 不修改翻译规则或 L0–L2 批准条件，不修改缺少合同的拒绝行为。
- 不把 QEMU 的运行结果描述为 RISC-V 真机 cache、PMU 或推测执行观察。
- 不把构建命令中的 Python 包装器描述为实际编译器。
- 不从实验合同期望值填充统计平台身份、编译器身份、campaign 语义事实或 attribution proof verifier。相应高级路线仍须提供独立依据，缺少时严格拒绝。
- 不移除受控 M-mode 系统路线与通用用户态 L3 provider 的环境冲突保护。016/022 的受控系统 L3 需要专门的适用机制，不能直接拼接用户态配置。
- 现有直接调用的比较器测试兼容旧协议；正常自动生产评估带新执行上下文，并强制要求新回包 envelope。旧观察器不会被自动升级为已验证。
- L3 验收只证明声明的属性、单位、关系和观察范围；不声称跨 ISA 的物理微架构完全等价。

## 新增入口与协议

自动批处理：

```
--l3-intent-producer-directory DIR
--l3-provider-directory DIR
--require-l3
```

生产器目录按已有目录绑定约定提供 `<sourceRelativePath>.l3-intent-producer.json`。文件名用于关联输入；是否适用由源码摘要、真实 fragment、编译器闭合和 proof 绑定判定，不能由文件名授予权限。`experiment_environment` 支持封存 `l3_intent_producer_directory`。

生产器清单准备工具：

```bash
python3 -m riscv2x86_py.l3_intent_ingress --help
```

其 `--command-json` 必须指向**实际完成语义核查且已经审查**的生产器。不要用测试 fixture、打印预设 profile 的脚本或 `/bin/true` 代替。准备命令只封存选择和身份，不批准语义。

生产器请求 `riscv2x86.l3-intent-producer-request.v1` 包含实际源码、源码摘要、生产器身份、全部获批 finding 和 translation artifact。生产器返回：

```json
{
  "schemaVersion": "riscv2x86.l3-intent-producer-response.v1",
  "requestIdentity": "请求中的实际身份",
  "profiles": ["每个获批片段对应的完整 v1 意图对象"]
}
```

上面的数组仅解释格式，不是可提交的配置。完整属性必须由选定工具根据实际输入核查生成。`approvedTargetRelationIdentity` 必须等于实际获批 `effect_relation_set_identity`；这是批准关系的关联，不构成物理微架构保证。

正常自动翻译在报告旁保存 `.l3-intent-production.json`，其中包含工具选择、实际请求和响应。正式评估再次独立重放生产器；因此生产器应对固定输入产生确定的 profile，且源码、工具和编译器 snapshot 必须保持可用。

L3 观察器在原请求中收到新增 `executionBinding`：

```json
{
  "schemaVersion": "riscv2x86.l3-observer-execution-binding.v1",
  "contextIdentity": "sha256:实际上下文摘要",
  "invocationId": "本次执行的独立身份",
  "side": "source 或 target",
  "program": {
    "artifactId": "实际产物标识",
    "artifactPath": "实际绝对路径",
    "artifactDigest": "sha256:实际内容摘要",
    "buildIdentity": "实际构建记录身份"
  }
}
```

观察器必须实际使用此程序，并在原平台报告外层原样返回 `executionBinding`。仅回显本字段不能证明进行了测量：原平台报告、适用机制、attribution、统计样本、属性比较和中央 closer 的检查继续全部执行。生产验收要求完整平台报告、逐属性闭合和实际产物绑定。

## 本地更新和第一轮验证

以下命令不使用 `set -e`，不会因测试非零状态主动关闭终端。先切换至已推送的 `phase93-l3-production-ingress-context` 分支。不要丢弃本地源码修改或清理整个 build 目录。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase93-l3-production-ingress-context
git switch --track origin/phase93-l3-production-ingress-context
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PHASE93_ROOT="$(mktemp -d "$REPO/experiment/results/phase93-XXXXXX")"
printf 'PHASE93_ROOT=%s\n' "$PHASE93_ROOT"
cmake --build build -j2 > "$PHASE93_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE93_ROOT/build.log"
```

确认构建成功后：

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_*.py \
  pytools/tests/test_paper_evaluation.py \
  pytools/tests/test_batch_evaluation_cli.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_validation_configuration.py \
  pytools/tests/test_translation_validation.py \
  pytools/tests/test_evaluation_runner.py \
  pytools/tests/test_experiment_environment.py \
  pytools/tests/test_route_contract_regression_runner.py \
  --junitxml="$PHASE93_ROOT/focused.xml" \
  > "$PHASE93_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 60 "$PHASE93_ROOT/focused.log"
```

新增测试包含正常评估入口的实际构建上下文传递、报告往返、生产器身份变化、错误 proof、遗漏片段、重哈希篡改、旧 invocation、错误程序、观察期间文件变化，以及 L0–L2 成功不能满足强制 L3 验收。协议 fixture 不代表真实硬件观察。

## 真实 L3 实验的准备顺序

1. 明确首个实验的属性与观察单位，以及源/目标究竟是物理平台、模拟器还是受控模型。普通算术输入不能无依据地标记 `none`，也不必为每条指令捏造一个物理测量目标。
2. 选择并审查语义生产器，再用清单准备工具封存它；审核生产器是否确实验证编译器边界、source intent、批准关系、观察位置与非干扰范围。
3. 使用正常入口生成真实报告与 L3 requirement。此时可以只提供生产器目录进行准备运行；没有 provider 时不得宣称完成 L3。
4. 基于实际 profile、requirement、proof、构建产物和平台机制准备原有严格实验合同与 provider。重建摘要发生变化时应拒绝并调查，不能自动改写合同以匹配。
5. 先对声明支持范围内的一个真实输入，正常运行到中央闭合；然后进行合法变化和语义/身份负测，最后扩大组合范围。

运行形式如下。`$L3_INPUT`、`$L3_INTENT_DIRECTORY`、`$L3_PROVIDER_DIRECTORY`、`$L3_ENVIRONMENT` 必须来自上述实际准备，不要用空变量运行，也不要复用仅有 L2 配置的旧清单冒充 L3 配置：

```bash
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$L3_INPUT" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$PHASE93_ROOT/l3-production" \
  --experiment-environment "$L3_ENVIRONMENT" \
  --l3-intent-producer-directory "$L3_INTENT_DIRECTORY" \
  --l3-provider-directory "$L3_PROVIDER_DIRECTORY" \
  --require-l3 \
  > "$PHASE93_ROOT/l3-production.log" 2>&1
L3_STATUS=$?
printf 'l3_production_status=%s\n' "$L3_STATUS"
tail -n 80 "$PHASE93_ROOT/l3-production.log"
```

`--require-l3` 对选定输入的所有 requirement 要求 eligible，并核查完整 L0–L3 与实际执行证据。因此不要将未支持、非法或明确不适用输入混入“所有输入均实际完成 L3”的验收。32 项全量实验应另行报告意图覆盖、适用性、执行覆盖与原有层级结果；未知不是不适用，非法输入不是合法翻译覆盖率分母。

成功必须同时看到：

- `l3-production-acceptance.json` 的 `productionAcceptanceComplete=true`；
- 对应 L3 的 source/target 平台报告、实际 `executionBindings` 与完整 `fragmentResult`；
- 各 required property 的比较证据及声明范围；
- 原有层级仍然 verified，且配置与实际执行环境一致。

可对某份已保存的单输入 evaluation 独立再验收：

```bash
python3 -m riscv2x86_py.l3_production_acceptance --help
```

使用 `--evaluation 实际evaluation-result.json --output 新的验收文件.json`。工具不会把旧报告中的 not_run 改成成功。

## 最后回归

真实 L3 正向、负向验收完成后，保留此前有效的 016/022/024/029 backend、声明与 runner 环境变量，再运行：

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 "$CLANG10" \
  --output "$PHASE93_ROOT/regression" \
  --require-no-regression-skips \
  > "$PHASE93_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 30 "$PHASE93_ROOT/regression/regression.log"
```

回归通过和真实 L3 生产验收是两个条件，不能互相替代。016/022/024/029 原有 L0–L2 组合结果仍应独立保留。

## 本轮开发环境验证记录

- L3、报告消费者、配置与评估器相关集合：286 passed。
- 仓库选定回归集合：1399 passed，43 skipped，零失败。43 项因缺少实际 Clang/llvm-mc/RISC-V GCC/QEMU 或未选择受控 backend 而跳过，不是无跳过回归。
- 尝试收集整个 `pytools/tests` 时有 13 个收集错误：环境缺少 z3/unicorn，且旧 `test_cross_asm.py` 仍引用已不存在的 `translate_function`。没有把该次运行计为通过，也没有为本轮 L3 任务改写这些旧测试或放宽要求。
- `git diff --check` 通过；用户已有 build 产物修改没有纳入提交。
- 未执行用户主机上的 32 项真实组合、真实物理平台 L3 或最终无跳过回归；上面的软件测试不能替代它们。

查询本轮实际生产日志时，先看 `l3-production.log` 和 `l3-production-acceptance.json`，再看对应 `evaluation-result.json` 中 L3 的 `providerDetail`。重点核对 `fragmentResult`、`platformReports`、`executionBindings` 和失败原因；不要只看全局 `statusCounts`。意图入口错误可查询报告旁的 `.requirement-failure.json`，以及成功生成时保存的 `.l3-intent-production.json`。

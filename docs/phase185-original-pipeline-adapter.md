# Phase185：真实预处理输入接回原翻译框架

基线：远端 phase184-machine-proof-foundations，158b7714a96a30a0290d85fcb619972ae21ac64b。

## 本轮实现和结论边界

本轮纠正候选生成的复用边界，同时修复可恢复采集。不是完整 GMP 程序已经验证通过的声明。

| 项目 | 本轮实施 | 尚未证明/尚未实现 |
|---|---|---|
| A 实验范围 | 新输入适配收据单列展开实例数，源码位置数与依赖上下文数未知时保留 null；新路线不要求先采集整个目标库的466个C上下文 | 完整多配置语料计划和有证据的相关依赖闭包 |
| B 实例适用性 | 按绑定AST路径、类型及记录的常量查询合同分析源条件；输出逐实例分类 | 记录合同仍须独立审计；不是规范机器码消除或执行证明 |
| C 回填 | 新入口复用原 candidate_materialization，限定冻结CPP翻译单元，保留原始字节身份 | 原始宏/头文件修改权限及展开来源图未补齐 |
| D 复用 | 新入口调用原公开CLI/pipeline和原回填器；可绑定原 EvaluationRequest，交原 evaluation_cli 执行；独立重导出前端并重跑后端 | 未打通所有GMP接口合同；不支持时不自动切回历史整数路线 |
| E 前端 | 原始CPP解析失败时生成能力诊断；可对显式候选检查器依次执行真实采集并保留失败证据；记录执行环境范围 | 没有安装新版Clang；没有猜测Float类型；所有候选均失败时仍阻塞 |
| F 恢复 | 批次/续采逐项原子进度；恢复旧版中途失败目录中的独立收据，校验上下文、工具及产物 | 缺失或无效收据不计成功；单次恢复最多64个上下文 |
| G–L 工程与机器合同 | 保留已有严格检查与未知结论，明确新旧结果域 | 实际配置兼容、适用依赖/ABI/对象/规范指令覆盖/自然运行及效果合同仍需实现 |
| M–N 原评估/状态 | 新路线直接使用原评估请求与调度，不另写批准算法，不把候选生成成功当评估通过 | 历史native五阶段的完整事实生产和闭合规则未补齐 |

旧 native_project_translation 库保留，用于历史证据审计和回归；其 create CLI 现在必须显式加
--legacy-integer，避免继续把旧受限路线实验算作原通用翻译器实验。不要修改旧收据或覆盖旧目录。

新流程：真实CPP及实例绑定 → prepare 重导出原前端 → 原 cli/pipeline → 原候选回填器 →
显式原评估请求 → 原 evaluation_cli → 原验证器及适用审计。

--skip-verify 仅用于生成待外部验证的候选，不绕过原语义证明门，也不批准源码发布。
它是原CLI的候选模式。原框架返回needs_route/unsupported/failed时保留，绝不自动回退旧整数规则。
新增静态 check 检查内容/配方绑定；audit 才会独立运行原前端及后端，不能混称为同一操作。

## 1. 更新与回归

在已有 .venv-l2 中，分段执行。每段完成后先查看状态。不要把提示符或终端输出复制回命令。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE183_ROOT:?}"
git -C "$REPO" fetch origin phase185-original-pipeline-adapter
export PHASE185_TOOLING="$PREP_ROOT/tooling-phase185"
git -C "$REPO" worktree add --detach "$PHASE185_TOOLING" origin/phase185-original-pipeline-adapter
export PHASE185_ROOT="$(mktemp -d "$PHASE183_ROOT/phase185-XXXXXX")"
: "${PHASE185_ROOT:?}"
export PYTHONPATH="$PHASE185_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE185_CLI="$PHASE185_TOOLING/experiment/advance_native_closure.py"
export PHASE185_ORIGINAL="$PHASE185_TOOLING/experiment/run_native_original.py"
git -C "$PHASE185_TOOLING" rev-parse HEAD
printf 'PHASE185_ROOT=%s\n' "$PHASE185_ROOT"
```

```bash
python3 -m pytest -q -rs \
 "$PHASE185_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE185_TOOLING/pytools/tests/test_native_instance_applicability.py" \
 "$PHASE185_TOOLING/pytools/tests/test_native_acquisition_recovery.py" \
 "$PHASE185_TOOLING/pytools/tests/test_project_native_input.py" \
 "$PHASE185_TOOLING/pytools/tests/test_native_context_completion.py" \
 "$PHASE185_TOOLING/pytools/tests/test_candidate_materialization.py" \
 "$PHASE185_TOOLING/pytools/tests/test_evaluation_runner.py" \
 --basetemp="$PHASE185_ROOT/pytest" > "$PHASE185_ROOT/focused.log" 2>&1
PHASE185_STATUS=$?
printf 'focused_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/focused.log"
```

协议测试中的外部编译器/Ghidra边界使用显式fixture；它们验证接线和拒绝行为，不是GMP成功证据。
原有真实编译器测试若skip，必须记录原因，不计为实际跨架构通过。任一真实操作失败后，停止依赖它的后续步骤。

## 2. 固定旧候选的位置，仅把它用作真实输入定位/历史比较

```bash
export PHASE185_CANDIDATE="$(python3 -c 'import json,os; from pathlib import Path; print(json.loads((Path(os.environ["PHASE183_ROOT"])/"deployment/plan.json").read_text())["candidatePath"])')"
: "${PHASE185_CANDIDATE:?}"
export PHASE185_BUNDLE="$(python3 -c 'import json,os; print(json.load(open(os.environ["PHASE185_CANDIDATE"]))["bindingBundlePath"])')"
: "${PHASE185_BUNDLE:?}"
ls -lh -- "$PHASE185_CANDIDATE" "$PHASE185_BUNDLE"
```

当前candidate.json来自历史整数生成器，不直接转换成原框架的已批准结果。不得改其批准标志或替换其产物。

## 3. 对当前源条件进行有界分析

```bash
python3 "$PHASE185_CLI" inspect-instance-applicability \
 --candidate "$PHASE185_CANDIDATE" --output "$PHASE185_ROOT/instance-applicability" \
 > "$PHASE185_ROOT/instance-applicability.log" 2>&1
PHASE185_STATUS=$?
printf 'applicability_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/instance-applicability.log"
```

成功后再执行：

```bash
python3 "$PHASE185_CLI" check --input "$PHASE185_ROOT/instance-applicability/result.json"
cat "$PHASE185_ROOT/instance-applicability/result.json"
```

excluded-under-recorded-contracts 仅表示在记录合同下源分支被排除。该工具没有验证旧候选独立审计，
没有证明整函数机器码删除，也没有执行程序。canonicalMachineDisposition必须仍为unknown，执行标志为false。
unknown也不表示实际可执行。不要为命中实例去修改项目阈值或构造不合法的巨大参数。

## 4. 通过原前端适配真实CPP

```bash
python3 "$PHASE185_ORIGINAL" prepare --bundle "$PHASE185_BUNDLE" \
 --output "$PHASE185_ROOT/original-input" --timeout-seconds 600 \
 > "$PHASE185_ROOT/original-input.log" 2>&1
PHASE185_STATUS=$?
printf 'original_input_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/original-input.log"
```

成功后：

```bash
python3 "$PHASE185_ORIGINAL" check --input "$PHASE185_ROOT/original-input/result.json"
```

预期：输入字节未变；原前端在隔离input.i上重新导出并通过同一物理AST绑定；
expandedInstanceCount为实际数量；originalSourceEditAuthorized/semanticApproval/productionAcceptanceComplete均false。
旧上下文只记录searchEnvironment时，本轮不声称已恢复完整历史进程环境。

## 5. 执行原通用翻译后端和原候选回填

GHIDRA_INSTALL_DIR必须指向实际使用的Ghidra安装。不要用猜测的路径。

```bash
: "${GHIDRA_INSTALL_DIR:?请设置实际Ghidra安装目录}"
ls -lh -- "$GHIDRA_INSTALL_DIR/support/pythonRun"
python3 "$PHASE185_ORIGINAL" translate --input "$PHASE185_ROOT/original-input/result.json" \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
 --output "$PHASE185_ROOT/original-translation" --timeout-seconds 600 \
 > "$PHASE185_ROOT/original-translation.log" 2>&1
PHASE185_STATUS=$?
printf 'original_translation_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/original-translation.log"
```

先看原后端stdout/stderr以及attemptOutcomes。返回2时可能是原路线正确拒绝或环境失败，不能称迁移通过。
原后端无report/archive时无完整result，查看run-status.json及original-backend.stderr。
有result但含unsupported/needs_route/failed时保留它，定位原后端首个缺失事实/能力，禁止自动回退。

候选完整生成后再执行：

```bash
python3 "$PHASE185_ORIGINAL" check --input "$PHASE185_ROOT/original-translation/result.json"
python3 "$PHASE185_ORIGINAL" audit --translation "$PHASE185_ROOT/original-translation/result.json" \
 --output "$PHASE185_ROOT/original-audit" > "$PHASE185_ROOT/original-audit.log" 2>&1
PHASE185_STATUS=$?
printf 'original_audit_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/original-audit.log"
```

独立重导出同一冻结源的前端报告，再重跑原后端/回填器，比较原attempt归档、返回码及候选树内容。
originalBackendReplayComplete=true仍不是L0/L1/L2/L3完成，也不是实例执行。

## 6. 原评估工作链的入口

必须有真实输入域、比较策略、构建配方、验证计划和注册器生成的原EvaluationRequest。
不能把旧native-framework-request.v1当作EvaluationRequest，不能创建空输入或虚假provider凑通过。
下面的ORIGINAL_EVALUATION_REQUEST应指向既有原框架请求生产者生成并核对过的请求。
没有该请求时，先返回第5节结果；缺失的实验合同仍是明确阻塞。

```bash
: "${ORIGINAL_EVALUATION_REQUEST:?需要真实原框架EvaluationRequest}"
python3 "$PHASE185_ORIGINAL" prepare-evaluation \
 --translation "$PHASE185_ROOT/original-translation/result.json" \
 --request "$ORIGINAL_EVALUATION_REQUEST" --output "$PHASE185_ROOT/original-evaluation-request.json"
```

适配器只重绑准确源/目标路径、原report和attempt归档，不改变层级、比较策略、构建或运行器合同。
此请求保留CPP产物域，不能扩展为原始源码修改或整个GMP的接受结论。
translationArtifacts为空时，由原评估器从本次原report/归档派生。非空映射必须与原产物工厂从本次运行
派生的事实完全一致；旧候选或其他运行的映射会被拒绝，不能当普通路径模板直接复用。
请求仍须核查：源构建实际消费该RISC-V输入；目标构建实际消费回填候选；链接和运行器使用预定产物；
编译参数与本实验配置对应。不得把旧原生库或无关函数产物替换进去。
冻结.i与新增requiredHeaders也必须由构建合同明确处理：直接按cpp-output编译时不能假设新#include会被处理，
重新预处理时也不能假设编译器内建宏和重复声明没有影响。缺少这种材料化合同就保持阻塞，不能删除头文件要求。

```bash
python3 -m riscv2x86_py.evaluation_cli \
 --request "$PHASE185_ROOT/original-evaluation-request.json" \
 --work-directory "$PHASE185_ROOT/original-evaluation" \
 --evaluation-output "$PHASE185_ROOT/original-evaluation-result.json" \
 > "$PHASE185_ROOT/original-evaluation.log" 2>&1
PHASE185_STATUS=$?
printf 'original_evaluation_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/original-evaluation.log"
```

查看实际执行层级、每层状态和原因。架构配置为L0–L2；L3按事先声明的意图/配置执行。
缺失L3证据不等于不适用。对sec_powm不能由整数输出一致推导时序或侧信道保持。

## 7. 恢复旧版第23项失败前的独立成功收据（次要，可后续执行）

此步骤用于维护依赖盘点，不是第4–5节原翻译入口的前置条件。
需要使用本轮工具重新审计部署并生成的新contracts，不能绕过旧部署的验证器身份检查。
先确认CURRENT_CONTRACTS是真实有效的本轮contracts路径。

```bash
: "${CURRENT_CONTRACTS:?需要本轮重新审计的contracts路径}" "${PHASE183_CLANG:?需要实际检查编译器}"
python3 "$PHASE185_CLI" recover-context-batch --contracts "$CURRENT_CONTRACTS" \
 --clang "$PHASE183_CLANG" \
 --receipt-root "$PHASE183_ROOT/context-completion-02/batch-000000" \
 --output "$PHASE185_ROOT/recovered-contexts" > "$PHASE185_ROOT/recovery.log" 2>&1
PHASE185_STATUS=$?
printf 'recovery_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/recovery.log"
```

该旧目录按已提供记录应有17–22六项。实际数量由校验决定，不硬编码；失败23不应计入成功。
成功后check新result，后续resolve-contexts或complete-context-inputs通过--context-batch引用它。
工具/上下文不相符、依赖或产物已变时拒绝复用；不因恢复需要而放宽检查。
旧v1收据新增环境记录的兼容：环境字段必须从原context重派生；重放仍逐项比较原context、原始CPP、
非AST输出和规范AST。缺少旧进程环境记录不会被补写成“已捕获”，也不赋予编译器等价或语义批准。

## 8. 对不兼容检查器选择替代工具（有替代工具时）

```bash
: "${CURRENT_CONTRACTS:?}" "${ALTERNATIVE_CLANG:?需要实际存在的候选检查器}"
python3 "$PHASE185_CLI" select-inspector --contracts "$CURRENT_CONTRACTS" --context-index 23 \
 --inspection-candidate "$PHASE183_CLANG" --inspection-candidate "$ALTERNATIVE_CLANG" \
 --output "$PHASE185_ROOT/inspector-selection" --timeout-seconds 600 \
 > "$PHASE185_ROOT/inspector-selection.log" 2>&1
PHASE185_STATUS=$?
printf 'inspector_selection_status=%s\n' "$PHASE185_STATUS"
cat "$PHASE185_ROOT/inspector-selection.log"
```

23是本次实验已定位的上下文索引，程序算法不依赖它。更换contracts时先核对实际索引。
候选必须是不同的真实可执行文件，最多8个。每次对相同原生配置执行真实采集，不替换类型、不屏蔽诊断。
inputAcquired=true仅意味着选中的正常native-input收据产生并通过校验；false时返回2，仍阻塞。
成功后可将selectedReceipt作为对应检查器批次的--reuse-receipt。统一检查器的续采器仍拒绝混合工具，
不能把不同工具收据伪装为同一工具；必要时按工具分批并由现有resolution检查器校验。

## 本轮应提供的最少结果

先提供focused.log和第3–5节实际生成的result及日志。后端失败时提供其stderr和run-status.json。
第6节仅在有真实原EvaluationRequest时推进。不要对不存在的文件继续check/refine。
不要先重跑全部466个上下文，也不要以历史native局部候选通过代替新原路线通过。

完整机器ABI事实生产、内部对象访问证明、规范实例指令覆盖、宏来源及历史native五阶段闭合仍需开发。
本轮没有把这些标志改真，没有把诊断/插桩结果升级成自然运行或整程序语义等价。

## 本地验证记录

45模块扩大回归604通过、8跳过（464.49秒）；最终采集/适配44通过、2跳过（63.78秒）；
最终请求绑定/原回填评估49通过（8.45秒）。组间重叠，不相加。
跳过原因包括缺少Clang/RISC-V GCC/QEMU/真实前端以及ptrace不可用；没有计为通过。
扩大回归首次启动漏传PYTHONPATH，5个子进程导入失败；保留首次日志，按本指南环境重跑整组后通过，
没有为这些失败更改断言或放宽检查。记录位于experiment/baselines/phase185/。
本地没有Ghidra及跨架构工具链，没有完成真实原后端翻译运行或GMP整程序验证。

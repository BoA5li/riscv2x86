# Phase188：从已审计原候选接入原评估器，固定语料分母并恢复进度

基线：phase187-wide-integer-original，27c4ebd50619b5fa53bb264d0775d9047cbf9783。
主机已提供：102 项回归通过；真实原候选 emitted；原后端及回填独立重跑通过。
这些证明候选链完成，尚不证明 GMP 程序执行、规范实例覆盖或整个语料库验证完成。

## 实施范围与正确性边界

| 问题 | 本轮实现 | 保留的边界 |
|---|---|---|
| run 只执行候选链 | 新 evaluate 调用原 evaluation.run_evaluation，原 materializer、构建和 translation_validation 分层调度不变 | 没有新增翻译器、验证器、整数回退或通过算法 |
| 真实请求接入不透明 | inspect 报告请求缺失、原计划所需层级和未声明 runner；绑定函数可独立派生并拒绝不完整翻译 | 请求可解析不等于输入合法或语义前提完整；缺 runner 仍可执行采集诊断，但原评估器返回不确定 |
| 评估进展难定位 | 逐尝试列出原结果、实际层级、profile、原因及构建是否被报告 | L0 不等于 L1；函数入口、静态机器事实不升级为实例执行覆盖 |
| 评估和审计混淆 | 冻结当前已独立审计的原 run、请求、计划、环境及全部本轮评估目录文件，重新派生摘要 | check 是记录一致性和产物检查，不是独立程序级重跑证明；independentProgramAuditPerformed=false |
| 语料结果分母和恢复 | 固定全部 seedId/bundle/request；所有样本从开始就在 progress 中；限量执行、逐项落盘、显式失败重试 | 不删除 unsupported/blocked/未执行项；没有从目录存在推定成功 |
| 协议分化 | 单个和批量入口均调用 native_original_pipeline.run 和原 evaluation.run_evaluation | 不消费历史 native_project_translation 的局部整数候选批准协议 |

本轮未实现完整机器 ABI、内部 C 访问/循环/调用效果证明、优化实例到规范指令区域的映射、
原始宏编辑权限，也未自动证明整个 GMP 的输入域和程序关系。已有有限机器/对象组件不能代替这些能力。
原评估结果即使 verified，其范围也由显式请求和原 profile 决定；本适配器的 semanticApproval 和
productionAcceptanceComplete 始终为 false，不签发额外最终批准。

## 1．更新并执行回归

以下各段分开执行，检查退出状态后再继续依赖步骤。保持已有 .venv-l2，不要求升级工具链。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE187_ROOT:?}"
git -C "$REPO" fetch origin phase188-original-evaluation-bridge
export PHASE188_TOOLING="$PREP_ROOT/tooling-phase188"
git -C "$REPO" worktree add --detach "$PHASE188_TOOLING" origin/phase188-original-evaluation-bridge
export PHASE188_ROOT="$(mktemp -d "$PHASE187_ROOT/phase188-XXXXXX")"
: "${PHASE188_ROOT:?}"
export PYTHONPATH="$PHASE188_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE188_ORIGINAL="$PHASE188_TOOLING/experiment/run_native_original.py"
export PHASE188_EVALUATE="$PHASE188_TOOLING/experiment/evaluate_native_original.py"
git -C "$PHASE188_TOOLING" rev-parse HEAD
printf 'PHASE188_ROOT=%s\n' "$PHASE188_ROOT"
```

```bash
python3 -m pytest -q -rs \
 "$PHASE188_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 "$PHASE188_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE188_TOOLING/pytools/tests/test_wide_integer_original.py" \
 "$PHASE188_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE188_TOOLING/pytools/tests/test_evaluation_runner.py" \
 "$PHASE188_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE188_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 --basetemp="$PHASE188_ROOT/pytest-focused" > "$PHASE188_ROOT/focused.log" 2>&1
PHASE188_STATUS=$?
printf 'focused_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/focused.log"
```

本轮新集成测试使用实际 pypcode、原 Pipeline、证明、渲染、回填及原评估器；前端、源汇编器和
Ghidra 启动数据有显式 fixture。copy-build 只用于协议测试，缺 L0 provider 必须返回不确定。
这些测试不作为真实 GMP 构建或执行成功的证据。

## 2．在本轮代码下重新生成真实候选

验证器源码清单变化后不能沿用上一轮 run 收据，不能重签旧收据或删除身份检查。
复用原始真实 bundle，重跑新候选链；无需再次采集 466 个依赖上下文。

```bash
: "${PHASE185_BUNDLE:?需要已有真实binding-bundle.json}"
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2_PUBLIC
test -x "$GHIDRA_INSTALL_DIR/support/pythonRun"
python3 "$PHASE188_ORIGINAL" run --bundle "$PHASE185_BUNDLE" \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" \
 --output "$PHASE188_ROOT/original-run" --timeout-seconds 600 \
 > "$PHASE188_ROOT/original-run.log" 2>&1
PHASE188_STATUS=$?
printf 'original_run_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/original-run.log"
```

返回 0 且最终文件存在后：

```bash
python3 "$PHASE188_ORIGINAL" check --input "$PHASE188_ROOT/original-run/result.json"
python3 "$PHASE188_EVALUATE" inspect --run "$PHASE188_ROOT/original-run/result.json" \
 > "$PHASE188_ROOT/evaluation-readiness.json"
PHASE188_STATUS=$?
printf 'inspection_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/evaluation-readiness.json"
```

不传请求时 inspect 预期返回 2，明确列出 EXPLICIT_ORIGINAL_EVALUATION_REQUEST_REQUIRED。
这是缺少下一阶段输入，不能据此认定宽乘法翻译失败。

## 3．明确真实评估合同后接入

PHASE188_REQUEST_TEMPLATE 必须指向实际原 EvaluationRequest JSON，不能使用旧 native 候选收据、
deployment/plan.json 或任意机器/对象模型充当请求。
协议由 pytools/riscv2x86_py/evaluation.py 的 evaluation_request_from_dict 严格解析。
需要的真实输入如下，尚没有的部分应提供实际记录后补齐，不能复制测试 fixture：

| 输入 | 必须核对 |
|---|---|
| sourceBuild | 实际 RV64 编译/链接命令、ABI、相关选项及依赖；本轮 SOURCE_PATH 是冻结 input.i |
| targetBuild | 实际 x86 编译/链接命令；消费本轮 TARGET_PATH；工程替换应绑定候选对象、库和测试程序 |
| validationPlan | profile、源/目标 runner、种子、超时、registry 版本；L3 只按声明意图和适用性要求执行 |
| targetEnvironment | 与实际运行和工具能力一致的源目标 ISA/ABI、runtime/loader 身份 |
| runtimeRegistryTemplate | 原 runner/provider 描述、合法入口/输入、比较合同；允许原评估器支持的变量，不能写旧产物身份冒充新构建 |
| comparisonPolicy | 输出、错误、退出、超时及适用效果的明确比较范围 |
| translationArtifacts | 留空时由原报告工厂派生；非空必须与当前运行的原工厂产物完全一致 |

validationPlan 和 targetEnvironment 使用绝对路径；注册器内嵌或外部证据仍由原 provider 检查。
本轮绑定会替换 sourceRoot、源目标相对路径、report、attemptArchive，并清空重复翻译命令；
不会改写构建命令、比较策略、层级和 registry 来促成通过。
当前语料入口只接受 program 单元，不允许从完整样本中静默挑一个成功 attempt。

有该真实请求时分段执行：

```bash
: "${PHASE188_REQUEST_TEMPLATE:?需要真实原EvaluationRequest文件路径}"
python3 "$PHASE188_EVALUATE" inspect \
 --run "$PHASE188_ROOT/original-run/result.json" \
 --request "$PHASE188_REQUEST_TEMPLATE" \
 > "$PHASE188_ROOT/evaluation-readiness-with-request.json"
PHASE188_STATUS=$?
printf 'inspection_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/evaluation-readiness-with-request.json"
```

inspect 的返回 0 仅表示请求可绑定，不表示所有 runner/语义前提已经具备。继续看 gaps。

```bash
python3 "$PHASE188_EVALUATE" evaluate \
 --run "$PHASE188_ROOT/original-run/result.json" \
 --request "$PHASE188_REQUEST_TEMPLATE" \
 --output "$PHASE188_ROOT/program-evaluation" \
 > "$PHASE188_ROOT/program-evaluation.log" 2>&1
PHASE188_STATUS=$?
printf 'evaluation_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/program-evaluation.log"
```

退出 0 表示原评估器的该请求结果 verified；退出 1 表示原评估已产生 failed/inconclusive 等结果；
退出 2 表示编排/输入异常。退出 1 可以有完整 result.json，需要检查原因，而不是当文件不存在。
只有 result.json 存在时执行：

```bash
python3 "$PHASE188_EVALUATE" check --input "$PHASE188_ROOT/program-evaluation/result.json"
```

重点文件：

- program-evaluation/request.json：绑定本轮候选后的原请求；
- program-evaluation/evaluation-result.json：原评估器完整结果，包含层级 detail/诊断；
- program-evaluation/result.json：适配器的输入绑定、文件清单和逐层摘要；
- program-evaluation/evaluation/replay/：原评估器实际注册器、重放记录和失败诊断；
- program-evaluation/run-status.json：编排异常时的具体阶段。

check 返回 0 只证明记录及所捕获产物一致，不表示程序独立审计通过。
若当前没有真实 EvaluationRequest，先提供 evaluation-readiness.json 和原始 bundle/源构建记录，
以及当前目标编译与测试命令；不要继续执行缺少请求的 evaluate，也不要为通过先填写虚假的合同。

## 4．真实语料清单与限量恢复

输入 JSON 的精确格式如下。各路径换成真实值，所有计划样本保留；requestPath=null 明确表示
本样本当前只推进翻译，不代表完整验证，也不会令整个调度返回验证成功。

```json
{
  "schemaVersion": "riscv2x86.native-original-corpus-input.v1",
  "seeds": [
    {"seedId": "stable-experiment-id", "bundlePath": "/actual/binding-bundle.json", "requestPath": null}
  ]
}
```

清单内容应来自实验选择，而不是成功结果过滤。一个 seed 可包含多个展开实例，466 个构建依赖
上下文不是 466 个翻译种子；源码位置、展开实例和配置变体仍需分别统计。

```bash
: "${PHASE188_CORPUS_INPUT:?需要真实完整实验清单JSON}"
python3 "$PHASE188_EVALUATE" freeze-corpus --input "$PHASE188_CORPUS_INPUT" \
 --output "$PHASE188_ROOT/corpus-plan.json"
```

```bash
python3 "$PHASE188_EVALUATE" run-corpus --plan "$PHASE188_ROOT/corpus-plan.json" \
 --output "$PHASE188_ROOT/corpus-run" --max-seeds 1 \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" --timeout-seconds 600 \
 > "$PHASE188_ROOT/corpus-first.log" 2>&1
PHASE188_STATUS=$?
printf 'corpus_status=%s\n' "$PHASE188_STATUS"
cat "$PHASE188_ROOT/corpus-first.log"
```

```bash
python3 "$PHASE188_EVALUATE" check --input "$PHASE188_ROOT/corpus-run/progress.json"
python3 "$PHASE188_EVALUATE" run-corpus --plan "$PHASE188_ROOT/corpus-plan.json" \
 --output "$PHASE188_ROOT/corpus-run" --max-seeds 1 --resume \
 --ghidra-install-dir "$GHIDRA_INSTALL_DIR" --timeout-seconds 600 \
 > "$PHASE188_ROOT/corpus-resume.log" 2>&1
```

普通 resume 仅处理 not_run。对编排异常的 blocked 样本，明确加 --retry-blocked，保留旧失败目录，
若已记录且通过检查的原候选收据存在则只重试评估。failed/inconclusive 的有效原评估结果不会被
无条件重跑抹去；修改合同需新计划/新输出。计划、工具验证器和已捕获证据变化均拒绝静默复用。
进程中断留下的 running 会成为 blocked，不能因目录存在认为成功；需显式重试。
run-corpus 的 timeout-seconds 用于原候选采集阶段；评估命令的超时继续由显式 validationPlan
及原 runner/provider 合同决定，调度器不会暗中改写这些合同。

progress.json 始终包含全部样本。allSeedsProcessed 只表示每个样本已处理至当前终态，可能含 blocked。
statusCounts 按实验样本统计，attemptOutcomeCounts 按已检查收据中的展开尝试统计；两者不是同一分母。
原后端返回 unsupported/needs_route 时，已产生的翻译收据和实际尝试结论保留在 blocked 样本中，
而不是只剩一个通用错误，更不能把该样本从分母删除。
CLI 仅在全部为 evaluation_verified 时返回 0；只完成翻译、部分预算执行、失败或不确定均返回 1。
即使全部原请求 verified，本调度器也不签发超出其请求范围的语义/生产批准。

## 后续必须由真实证据继续推进

先观察本轮新候选的原 L0 构建结果，再修复实际报告的构建/链接接口问题；不要在尚未运行 L0 时
推断它一定失败。随后在合法入口/输入合同下推进 L1，补适用机器 ABI、内部对象访问和调用效果、
规范实例存续/消除及实际事件，再接入所需 L2/L3 与独立程序审计。
历史已排除实例不能从统计分母删除；规范产物是否消除或运行命中需对应配置的新证据。
不能靠修改 GMP 阈值、强行不合法输入、入口探针命中或 sanitizer 有限测试填满整体证明标志。

## 本地验证记录

最终稳定代码：新入口集成测试 12 项通过；原相关模块联合回归 104 项通过，两组不重叠，
合计 116 项选定测试通过。日志和测试边界见 experiment/baselines/phase188/。
没有宣称全仓库测试全部通过，也没有在本环境执行用户主机上的真实 GMP 全链评估。

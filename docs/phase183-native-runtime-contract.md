# Phase183：原L0接口契约与C上下文自动续采

父远端提交：a3f9cd51e9c9e00d2d812f51f9a6f0298ef1466b。

## 实际范围

本轮修复native适配器的runtime.none版本缺失，并增加原L0消费者链的常规契约回归。
新增complete-context-inputs自动消费所有预算内、受支持的C编译上下文，复用已检查批次，
中断后保留可复验子批次。它不把C上下文采集等同于完整依赖/汇编接口闭包。

**本轮没有实现全部机器ABI、内部对象访问、自然运行规范指令覆盖与完整L1–L3证明。**
这些模块不是补齐JSON字段即可完成。原准入保持严格；没有引入用户填写verified的捷径。
必须以实际函数及外部调用的支持范围、前置条件和效果模型为依据，逐项生产/检查证据。
对于尚不支持的情况，完整执行的正确结果仍是inconclusive，不能宣称语义等价。

## 原因与修复

native_framework_admission原先输出runtimeContractVersion空字符串，原L0清单要求非空。
本轮与translation_artifact_binding复用runtime_dependency_binding中的runtime.none/v1约定。
此约定仅表示翻译不新增辅助运行时依赖，不表示GMP/libc依赖语义已经闭合。
构建前另按注册的runtime helper semantic_version核对真实版本，拒绝虚构的非空版本及未知合同。

l0_artifact_manifest和l0_manifest_builder共用元数据绑定检查，编译前拒绝空proof、
运行时标识/版本和recipe。生成器实际构造18单元后，还经过原公开清单解析、序列化及
文件摘要加载往返检查，避免返回消费者不可读的清单。原完整单元和产物绑定要求保留。

test_native_l0_contract不依赖RV工具链：用明确的命令/ELF协议fixture测试native导出、
原TranslationArtifact解析、原18单元生成器、原清单解析及_check_manifest_binding。
这验证接口，不证明真实编译成功。test_native_l0_materialization仍保留真实交叉构建测试。

## 一、固定新工具，先验证L0接口

旧目录不覆盖。请逐块执行，失败后停止依赖步骤，先返回首个失败日志。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE182_ROOT:?}"
git -C "$REPO" fetch origin phase183-native-runtime-contract
export PHASE183_TOOLING="$PREP_ROOT/tooling-phase183"
git -C "$REPO" worktree add --detach "$PHASE183_TOOLING" origin/phase183-native-runtime-contract
export PHASE183_ROOT="$(mktemp -d "$PHASE182_ROOT/phase183-XXXXXX")"
: "${PHASE183_ROOT:?}"
export PYTHONPATH="$PHASE183_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE183_CLI="$PHASE183_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE183_TOOLING" rev-parse HEAD
printf 'PHASE183_ROOT=%s\n' "$PHASE183_ROOT"
```

```bash
python3 -m pytest -q -rs \
 "$PHASE183_TOOLING/pytools/tests/test_native_l0_contract.py" \
 "$PHASE183_TOOLING/pytools/tests/test_native_entry_probe.py" \
 "$PHASE183_TOOLING/pytools/tests/test_native_framework_admission.py" \
 "$PHASE183_TOOLING/pytools/tests/test_native_l0_materialization.py" \
 "$PHASE183_TOOLING/pytools/tests/test_native_context_completion.py" \
 --basetemp="$PHASE183_ROOT/pytest-focused" > "$PHASE183_ROOT/focused.log" 2>&1
PHASE183_STATUS=$?
printf 'phase183_focused_status=%s\n' "$PHASE183_STATUS"
cat "$PHASE183_ROOT/focused.log"
```

## 二、建立本轮基本证据，无须先采齐466项才测试L0

新代码改变验证器清单，必须重新审计部署，不手改旧审计或清单。
以下为沿用phase181分步指南的显式变量映射：输出仍在新PHASE183_ROOT内。

```bash
: "${PHASE179_ROOT:?}"
export PHASE181_TOOLING="$PHASE183_TOOLING"
export PHASE181_ROOT="$PHASE183_ROOT"
export PHASE181_CLI="$PHASE183_CLI"
export PHASE181_PLAN="$PHASE179_ROOT/deployment/plan.json"
export PHASE181_CLANG="$(command -v clang-10)"
: "${PHASE181_CLANG:?}"
```

执行[phase181指南](phase181-native-api-admission.md)第3–7步，得到本轮
contracts-with-runtime/result.json。不要执行其第1步再创建旧工具目录。
可以先以此作为基础合同测试L0并导出接口模板，不必先采齐全部C上下文或等待整体ABI通过。

```bash
export PHASE181_BASE="$PHASE183_ROOT/contracts-with-runtime/result.json"
python3 "$PHASE183_CLI" prepare-api --contracts "$PHASE181_BASE" \
 --output "$PHASE183_ROOT/api-plan.json"
```

先保留api-plan.json供核对实际接口和前置条件。实际API执行不能使用空cases或猜测输入。
现在可以执行phase181指南第19步的materialize-native-l0、prepare-native-l0-request和
run-framework，PHASE181_ROOT/BASE已指向本轮。该步骤不依赖API成功；是独立的原L0构建验证。
其源ISA、QEMU路径必须与实验实际设置一致。失败保留首个日志，不删除矩阵单元。
不要混用此基础合同与后续refine后不同身份的API/语句/framework子证据。

## 三、自动续采C上下文

需要已经检查的基础v3合同，不接受已经消费context-resolution的派生报告，防止递归。
先做小预算，确认源文件和工具有效，再按预算推进。可将已有同一基础合同的seed/priority
批次通过重复--context-batch传入；不同合同或不同检查编译器的回执被拒绝。

```bash
python3 "$PHASE183_CLI" complete-context-inputs \
 --contracts "$PHASE183_ROOT/contracts-with-runtime/result.json" \
 --clang "$PHASE181_CLANG" --max-contexts 16 --batch-size 4 \
 --timeout-seconds 600 --output "$PHASE183_ROOT/context-completion-01" \
 > "$PHASE183_ROOT/context-completion-01.log" 2>&1
PHASE183_STATUS=$?
printf 'context_completion_status=%s\n' "$PHASE183_STATUS"
cat "$PHASE183_ROOT/context-completion-01.log"
```

```bash
python3 "$PHASE183_CLI" check \
 --input "$PHASE183_ROOT/context-completion-01/result.json"
```

下一轮续采及接回原resolution：以下复验上轮completion，从其batchResultPaths生成原CLI
参数；不会重新编译已有成功上下文。max-contexts可按资源调整到466或更大预算（上限10000），
每个子批次仍不超过64，逐上下文超时单独计时，并非整个操作的总超时。

```bash
python3 - <<'PY' > "$PHASE183_ROOT/context-completion-02.log" 2>&1
import os,subprocess,sys
from pathlib import Path
from riscv2x86_py.native_context_completion import check
root=Path(os.environ['PHASE183_ROOT'])
previous=check(root/'context-completion-01/result.json')
cmd=[sys.executable,os.environ['PHASE183_CLI'],'complete-context-inputs',
 '--contracts',str(root/'contracts-with-runtime/result.json'),'--clang',os.environ['PHASE181_CLANG'],
 '--max-contexts','466','--batch-size','16','--timeout-seconds','600',
 '--output',str(root/'context-completion-02')]
for path in previous['batchResultPaths']:cmd+=['--context-batch',path]
raise SystemExit(subprocess.call(cmd))
PY
PHASE183_STATUS=$?
printf 'context_completion_retry_status=%s\n' "$PHASE183_STATUS"
cat "$PHASE183_ROOT/context-completion-02.log"
```

若某子批次编译失败，顶层result.json不会生成，已完成的batch-*/result.json保留。
新目录重试时通过--context-batch传入这些文件；每份仍经过原batch.check和上下文/工具核验。
不使用未完成批次目录或伪造失败回执。日志逐批输出进度。

```bash
python3 - <<'PY' > "$PHASE183_ROOT/completion-resolution.log" 2>&1
import os,subprocess,sys
from pathlib import Path
from riscv2x86_py.native_context_completion import check
root=Path(os.environ['PHASE183_ROOT'])
report=check(root/'context-completion-02/result.json')
cmd=[sys.executable,os.environ['PHASE183_CLI'],'resolve-contexts',
 '--contracts',str(root/'contracts-with-runtime/result.json'),'--output',str(root/'context-resolution-complete')]
for path in report['batchResultPaths']:cmd+=['--context-batch',path]
if not report['batchResultPaths']:raise ValueError('NO_CONTEXT_BATCH_AVAILABLE_FOR_RESOLUTION')
raise SystemExit(subprocess.call(cmd))
PY
PHASE183_STATUS=$?
printf 'completion_resolution_status=%s\n' "$PHASE183_STATUS"
cat "$PHASE183_ROOT/completion-resolution.log"
```

allCapturedCContextsAcquired只表示所有捕获到的C上下文已取得回执，不表示全部源文件覆盖、
汇编接口闭包、程序可达性、ABI或语义通过。blockedContexts必须保留，不默认为不执行。
若remainingEligibleContextIndices非空，应继续预算续采；若只余blockedContexts，停止
重复采集，按其原因处理生产来源或不支持的上下文。

## 四、整体工作链仍缺的检查器

详细边界见[phase182说明](phase182-entry-location-contract.md)“必须区分的剩余工作”。
当前尚不能从现有输入自动产生完整机器ABI、callee内部对象访问合法性、规范实例指令覆盖
及所有外部效果的证明。不能写一个接受手工verified的通用JSON接口来冒充这些检查器。

下一份必要信息是本轮api-plan.json及实际函数前置条件的权威来源；它们用于确定受限API
支持范围和生成有效输入。若缺少调用效果/对象关系模型，继续明确列义务，不能直接开放L1–L3。
当前合同派生和原准入保持严格，因此仍可能正确报告inconclusive。

本轮验收分别检查：接口回归通过、真实L0矩阵通过、C上下文采集进展、GMP入口观察、
受限API观察、整体合同闭合。不要用其中任何一项替代其他项目。

## 本地回归记录

28模块联合回归424通过、5跳过（567.00秒）；最终运行时接口回归40通过；
最终新增契约/续采回归23通过。这些组存在重叠，不相加。
跳过2个ptrace路径及3个真实跨架构路径，均未记为通过。
日志、模块列表及摘要位于experiment/baselines/phase183/。
本机没有执行真实GMP整程序接受，也未实现全部整体阶段闭合能力。

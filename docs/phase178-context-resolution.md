# Phase178：消费上下文回执、精确符号候选与可追溯归档诊断

本轮基于 phase177-producer-context-scope。输入证据是用户实际运行的253项回归、
完整诊断端点映射、533个生产者节点/466个C上下文、1个归档缺口/65个汇编合同义务，
以及首批4个有效回执（1个父回执复用、3个新采集）。这些事实不等于程序语义通过。

## 修订方案和实际实现

| 缺口 | 实现 | 严格边界 |
| --- | --- | --- |
| 归档追溯丢失底层失败原因 | native_link_contexts 保存各捕获配置的选择结果、完整候选数、动作身份/参数/时间及前后快照摘要 | 不改变唯一链、成员摘要和时间顺序验证；历史缺少证据仍阻塞 |
| 汇编生产者与接口混为一谈 | 同模块导出实际ELF定义/未定义符号及其类型、绑定、可见性 | STT_OBJECT数据、STT_NOTYPE和IFUNC不能冒充普通函数ABI |
| 批次回执没有消费者 | native_context_resolution 读取已核验回执，调用原 ast_graph/local_scope 和ELF解析器，关联声明、定义及精确对象中的符号，并通过refine-contracts消费回原合同报告 | 这是原工作链输入/调用关系消费者；不生成第二套翻译结果或批准逻辑 |
| 同名或弱定义误配风险 | 必须有编译器发出的mangledName；按精确生产对象和符号表项关联定义；保留内部链接、多定义、弱符号、类型差异 | 不按项目函数名匹配，不用源码名称猜链接符号，不把唯一可见候选当实际链接选择 |
| 候选替换后仍可能分析原定义 | 同时核对原对象canonical路径和摘要，以审计候选图/对象替换生产者分析单元 | 同名或相同字节的其他对象不能替代；原生目标上下文关系仍独立 |
| 大量无差别采集 | 从已知局部调用及未采集对象的真实导出符号产生 suggestedContextIndices | 仅优先级；不能证明未选上下文不可达；汇编/归档仍保留 |
| 更换验证器后重复CPP/AST采集 | inspect-context / inspect-contracts / acquire-context-batch 显式接收旧原生输入回执，重新检查内容、工具、依赖、完整上下文和目标 | 复用采集事实，不复用旧验证器审计结论；不篡改旧身份；冲突或上下文改变拒绝 |

## 本轮不能宣称已完成的工作

原 function_abi_machine_join 仍需要正确的声明、机器、CFG和帧事实；原sidecar仅接受
RV64标量profile，不能凭空构造x86 complete事实。本轮符号候选及signature形状关系
不是原生ABI证明，也不是编译器类型兼容性的完整决定过程（尤其是记录布局/可变参数）。

归档具体历史缺口必须由新增诊断识别；尚未证明链完整时不自动挑选成员。
汇编接口尚不含函数体效果、寄存器保存或对象初始化合同。
PIC显式参数差异仍需实际编译配置/产物关系，不能自动忽略。
合法对象域、源目标同输入、候选实例执行、适用L0–L3准入及独立程序级审计仍未完成。
不能把本轮操作返回0解释为五个实验阶段全部完成。

## 验证顺序

验证器源码清单改变，必须重新audit/deploy/observe/capture；这保持原身份约束。
原CPP/AST采集可按下述方式独立重新验证后复用。每步成功后再执行下一步。
若失败，保留首个失败日志，不检查未生成的result.json；不修改原始编译参数压过失败。
所有工具输出目录应尚不存在，mktemp只创建其父目录。

### 1. 获取工具并固定输入

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE177_ROOT:?}" "${PHASE177_BATCH_PARENT:?}"
git -C "$REPO" fetch origin phase178-context-resolution
export PHASE178_TOOLING="$PREP_ROOT/tooling-phase178"
git -C "$REPO" worktree add --detach "$PHASE178_TOOLING" origin/phase178-context-resolution
export PHASE178_ROOT="$(mktemp -d "$PHASE177_ROOT/phase178-XXXXXX")"
: "${PHASE178_ROOT:?}"
export PHASE178_PLAN="$PHASE177_ROOT/deployment/plan.json"
export PHASE178_CLANG="$(command -v clang-10)"
: "${PHASE178_CLANG:?}"
export PYTHONPATH="$PHASE178_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE178_TOOLING" rev-parse HEAD
printf 'PHASE178_ROOT=%s\n' "$PHASE178_ROOT"
```

### 2. 回归

```bash
python3 -m pytest -q -rs \
  "$PHASE178_TOOLING/pytools/tests/test_native_context_resolution.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_link_contexts.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_program_scope.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE178_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE178_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  --basetemp="$PHASE178_ROOT/pytest" \
  > "$PHASE178_ROOT/focused.log" 2>&1
PHASE178_TEST_STATUS=$?
printf 'test_status=%s\n' "$PHASE178_TEST_STATUS"
cat "$PHASE178_ROOT/focused.log"
```

### 3. 新验证器审计和部署

以下每个命令应单独执行，确认成功再进行下一条。

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "$PHASE178_PLAN" --output "$PHASE178_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE178_ROOT/audit.log" 2>&1
PHASE178_AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$PHASE178_AUDIT_STATUS"
cat "$PHASE178_ROOT/audit.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "$PHASE178_PLAN" --input "$PHASE178_ROOT/candidate-audit/deployment-audit.json"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "$PHASE178_PLAN" --audit "$PHASE178_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE178_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE178_ROOT/deployment.log" 2>&1
PHASE178_DEPLOY_STATUS=$?
printf 'deploy_status=%s\n' "$PHASE178_DEPLOY_STATUS"
cat "$PHASE178_ROOT/deployment.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/deployment/result.json"
```

### 4. 本轮运行证据

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE178_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE178_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE178_ROOT/observation.log" 2>&1
PHASE178_OBSERVATION_STATUS=$?
printf 'observation_status=%s\n' "$PHASE178_OBSERVATION_STATUS"
cat "$PHASE178_ROOT/observation.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/observation/result.json"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" capture-runtime \
  --observation "$PHASE178_ROOT/observation/result.json" \
  --output "$PHASE178_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE178_ROOT/runtime.log" 2>&1
PHASE178_RUNTIME_STATUS=$?
printf 'runtime_status=%s\n' "$PHASE178_RUNTIME_STATUS"
cat "$PHASE178_ROOT/runtime.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/runtime-identity/result.json"
```

端点数随实际运行变化，不按301/602硬编码通过；检查完整性、失败原因和适用范围。

### 5. 复用核验过的原生目标采集

先从旧manifest提取真实回执路径，不能根据输出目录猜路径。

```bash
export PHASE178_REUSE_TARGET="$(python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE177_ROOT'])/'context-bridge/inputs.json'
print(json.loads(p.read_text())['targetReceipt']['path'])
PY
)"
: "${PHASE178_REUSE_TARGET:?}"
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE178_ROOT/deployment/plan.json" \
  --observation "$PHASE178_ROOT/observation/result.json" \
  --clang "$PHASE178_CLANG" --reuse-native-input "$PHASE178_REUSE_TARGET" \
  --output "$PHASE178_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE178_ROOT/context.log" 2>&1
PHASE178_CONTEXT_STATUS=$?
printf 'context_status=%s\n' "$PHASE178_CONTEXT_STATUS"
cat "$PHASE178_ROOT/context.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/context-bridge/result.json"
```

### 6. 复用入口回执生成新合同

下面脚本根据manifest枚举所有入口回执，不硬编码入口数量。

```bash
python3 - <<'PY' > "$PHASE178_ROOT/contracts.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE178_ROOT'])
old=Path(os.environ['PHASE177_ROOT'])/'contracts-with-runtime/inputs.json'
cmd=[sys.executable,str(Path(os.environ['PHASE178_TOOLING'])/'experiment/advance_native_closure.py'),
 'inspect-contracts','--context',str(root/'context-bridge/result.json'),
 '--observation',str(root/'observation/result.json'),
 '--runtime',str(root/'runtime-identity/result.json'),
 '--clang',os.environ['PHASE178_CLANG'],'--output',str(root/'contracts-with-runtime'),
 '--timeout-seconds','600']
for row in json.loads(old.read_text())['entryReceipts']:
 cmd.extend(['--reuse-entry-receipt',row['path']])
raise SystemExit(subprocess.call(cmd))
PY
PHASE178_CONTRACT_STATUS=$?
printf 'contracts_status=%s\n' "$PHASE178_CONTRACT_STATUS"
cat "$PHASE178_ROOT/contracts.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/contracts-with-runtime/result.json"
```

### 7. 重新绑定首批回执，不重复采集三个依赖

只把旧批次里实际新采集的回执作为复用参数；入口采用新父manifest，避免同一上下文
出现两套不同身份。所有复用文件都重新做工具、依赖、上下文和内容验证。

```bash
python3 - <<'PY' > "$PHASE178_ROOT/batch.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE178_ROOT'])
old=Path(os.environ['PHASE177_BATCH_PARENT'])/'evidence/result.json'
previous=json.loads(old.read_text())
cmd=[sys.executable,str(Path(os.environ['PHASE178_TOOLING'])/'experiment/advance_native_closure.py'),
 'acquire-context-batch','--contracts',str(root/'contracts-with-runtime/result.json'),
 '--clang',os.environ['PHASE178_CLANG'],'--start-index',str(previous['startIndex']),
 '--count',str(previous['nextIndex']-previous['startIndex']),
 '--timeout-seconds','600','--output',str(root/'context-batch')]
for row in previous['rows']:
 if row['nativeInputAcquired'] and not row['reusedParentReceipt']:
  cmd.extend(['--reuse-receipt',row['receipt']['path']])
raise SystemExit(subprocess.call(cmd))
PY
PHASE178_BATCH_STATUS=$?
printf 'batch_status=%s\n' "$PHASE178_BATCH_STATUS"
cat "$PHASE178_ROOT/batch.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/context-batch/result.json"
```

### 8. 执行新增消费者

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" resolve-contexts \
  --contracts "$PHASE178_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE178_ROOT/context-batch/result.json" \
  --output "$PHASE178_ROOT/context-resolution" \
  > "$PHASE178_ROOT/resolution.log" 2>&1
PHASE178_RESOLUTION_STATUS=$?
printf 'resolution_status=%s\n' "$PHASE178_RESOLUTION_STATUS"
cat "$PHASE178_ROOT/resolution.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/context-resolution/result.json"
```

可重复传入多个 --context-batch 累积同一合同下的非冲突批次。重复批次、错父身份、
同上下文冲突回执会失败；不能拼入上一验证器的旧合同批次。

### 9. 将结果接回现有合同工作链

消费者结果通过原refine-contracts入口生成v4合同。基础合同仍为v3；批次和解析始终
引用同一基础合同，避免产生循环依赖。v4会记录消费身份、实际上下文数量和调用
对应结果；不会因声明关系完成就把ABI或程序验收改为通过。

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" refine-contracts \
  --input "$PHASE178_ROOT/contracts-with-runtime/result.json" \
  --context-resolution "$PHASE178_ROOT/context-resolution/result.json" \
  --output "$PHASE178_ROOT/contracts-resolved" \
  > "$PHASE178_ROOT/refinement.log" 2>&1
PHASE178_REFINE_STATUS=$?
printf 'refine_status=%s\n' "$PHASE178_REFINE_STATUS"
cat "$PHASE178_ROOT/refinement.log"
```

```bash
python3 "$PHASE178_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE178_ROOT/contracts-resolved/result.json"
```

### 10. 导出一次性分析摘要

```bash
python3 - <<'PY' > "$PHASE178_ROOT/phase178-summary.json"
import json,os
from pathlib import Path
root=Path(os.environ['PHASE178_ROOT'])
c=json.loads((root/'contracts-with-runtime/result.json').read_text())
r=json.loads((root/'context-resolution/result.json').read_text())
f=json.loads((root/'contracts-resolved/result.json').read_text())
g=c['producerContextClosure']
print(json.dumps({
 'baseContractEvidenceIdentity':c['contractEvidenceIdentity'],
 'refinedContractEvidenceIdentity':f['contractEvidenceIdentity'],
 'consumedResolutionIdentity':f['contextResolution']['contextResolutionIdentity'],
 'contextResolutionIdentity':r['contextResolutionIdentity'],
 'stages':c['stages'],
 'archiveGaps':[gap for gap in g['inputGaps']
    if gap['reasonCode']=='ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE'],
 'consumedContextCount':r['consumedContextCount'],
 'remainingWorkReasonCounts':r['remainingWorkReasonCounts'],
 'callReasonCounts':r['resolution']['callReasonCounts'],
 'uniqueStrongFunctionCandidateCallCount':r['resolution']['uniqueStrongFunctionCandidateCallCount'],
 'suggestedContextIndices':r['resolution']['suggestedContextIndices'],
 'relatedWork':[w for w in r['remainingWork'] if w.get('relatedKnownLocalCallJoinIdentities')],
 'nativeAbiClosureVerified':r['nativeAbiClosureVerified'],
 'semanticApproval':r['semanticApproval']},indent=2,ensure_ascii=False))
PY
```

先提供 focused.log、contracts.log、resolution.log、refinement.log、phase178-summary.json。
据真实原因修订归档缺口；据建议索引小批采集相关上下文。不要在缺少消费者或执行
事实时一次处理全部466项。即使某一阶段返回完整，也要分别核查其声明的范围。

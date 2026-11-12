> 后续修订与回执消费验证见 [phase178-context-resolution.md](phase178-context-resolution.md)。

# Phase177：依赖生产者、调用范围与上下文批量采集

## 新材料确认的问题

基于phase176 `1d3152f58b75b8bfdf1869e51f076a6abdcb53b9`。
phase176的运行分片修复已经在真实GMP运行中取得602/602端点关联及301条元数据兼容
记录。本轮不修改这些通过条件，也不把这些数字作为其他语料的通过阈值。

完整合同、部署计划及上下文报告确认：

- 入口的两个库参数位置引用同一份原库。必须复用其生产事实而保留两个链接位置。
- 原库有530个显式对象输入；只采集一个测试入口AST不足以完成依赖上下文闭包。
- libtests.a需要按捕获的归档操作链追溯成员，不允许按basename或相同字节猜测来源。
- 664条源端/候选声明对应及签名检查已通过，所检查的数据模型字段一致；这些
  结论不能升级为原生ABI证明。
- 候选和原生生产参数存在显式PIC选项差异，预处理输出摘要也不相同。差异是待解释
  事实，不直接证明程序不等价。不得修改不可变候选对象或按项目函数名忽略差异。
- 入口AST里的未解析回调来自头文件函数；静态可见不等于本次执行。
- 目前ABI machine join缺少声明/机器/CFG/栈帧输入，对象和重定位主要在生成义务，
  原工作链的程序级准入尚未接通。不能通过改完成标志来补齐这些能力。

## 本轮实现的通用修订

| 实现 | 方法 | 证明边界 |
| --- | --- | --- |
| `native_link_contexts.py` | 重放原构建记录，递归追溯显式对象、共享库及普通ar归档；检查生产成功、时间先后、捕获时钟域、规范路径与摘要；保留所有链接位置 | 显式历史输入的生产者关系，不代表驱动器隐式依赖、实际归档提取、运行绑定或ABI |
| 归档成员 | 复用原有append/index操作验证器；按完整链、成员序号、headerOffset和实际输入路径绑定；保留同名成员 | 缺少捕获链时保持未绑定，不退化为内容匹配；thin/LTO等未建模输入不获批准 |
| 路径别名与重复库 | 同一规范产物和消费动作可复用节点；边仍保留参数位置和顺序；同字节不同规范路径不能选择生产者 | 不能删重复参数，不能在多个生产者间任意选一个 |
| 部署关系 | 记录原对象到候选对象、原库到派生库的已有精确替换关系 | 不要求不同产物摘要相同，也不把替换验证当作跨架构语义证明 |
| `native_program_scope.py` | 以实例绑定及已验证字节编辑声明关系确定源/候选根；对C hosted main检查入口符号和唯一声明；沿已知局部直接调用展开 | 未访问的函数不标为不可达；外部、回调、构造器、跨上下文关系仍有义务；不按名称过滤头文件函数 |
| 对象角色 | 区分extern声明、全局/暂定定义及函数局部声明，标注局部图中的位置 | 不把声明条数当作运行对象条数，不批准生命周期或边界 |
| `native_object_initializers.py` | 复用已有typed integer term核心，验证受支持的整数常量初始化表达式及有定义转换 | 仅是inspection层表达式值；不证明原生编译器等价、对象实际存在或输入合法 |
| `native_context_batch.py` | 按自动追溯的上下文列表，分批调用既有原生CPP/AST采集；复用父报告中同编译器、同上下文的有效回执 | 支持x86-64 C生产者；其他机器或不可检查上下文明确保留缺口；不授予ABI/对象/L0–L3批准 |
| 合同报告v3 | 自动关联生产者图、局部范围、PIC显式参数比较及有限初始化证据 | 保留旧的完整入口、ABI、对象和程序准入缺口；不能用新组件的成功替代其他合同 |

本轮新增的是可执行的生产者追溯、局部范围分析、有限表达式证明和批量采集能力，
不是完整C程序语义证明器。资源预算为4096个生产节点、256MiB显式输入字节；
超限明确失败。上下文批次最多64个、默认4个，避免一次对大型项目采集数百份AST。

### 如何理解报告中的几个不同完成标志

- `capturedProducerClosureComplete`：当前范围的显式历史输入都有捕获的生产者/归档链。
- `producerCompileContextCount`：可追溯到的C编译上下文数量，**不是已经完成AST采集的数量**。
- `selectedContextAcquisitionComplete`：某个批次的选中上下文取得有效回执，不代表全部批次或ABI通过。
- `entryCapturedInputContextCoverageComplete`：原有完整入口上下文条件；不能仅凭生产者图改为true。
- `knownLocalClosureComputed`：已计算局部直接边范围；未证明其余函数不可达。
- `inspectionTypedConstantInitializerVerified`：该有限表达式在检查模型中的常量值；运行对象合同仍独立。
- 显式PIC参数不同不等于编译效果不同。默认设置和机器效果还需相应证据。

## 后续完整验证仍需实现和取得的事实

| 工作 | 必须依据 | 禁止的替代做法 |
| --- | --- | --- |
| 原生ABI消费者接入 | 各端实际ABI声明、机器参数/返回值位置、CFG、栈帧和调用效果；为x86与RV64建立正确适配 | 将四个None换成凭空构造的complete事实；把只支持RV64的旧sidecar直接套给x86 |
| 三方上下文关系 | 冻结源CPP、候选字节编辑、原生目标CPP和相关声明/表达式的关系及实际编译配置 | 要求所有宏字节必须相同；或按项目宏、函数名无条件忽略差异 |
| 跨模块调用及回调 | 实际归属、版本、调用点类型、回调目标集、变参与内建合同 | 把所有缺少本地定义的调用都算作外部错误；把所有内建当普通函数 |
| 对象域 | 对象身份、合法输入域、初始化执行、存活期、大小/对齐、别名和前置条件 | 用AST里有初始化、表达式值已知或返回0代替运行对象证明 |
| 运行/重定位 | 适用的实际提供者、COPY初始化、IFUNC解析目标、TLS等事实及明确环境合同 | 将元数据兼容等同于全部内存效果或自然运行关系 |
| 程序观察和原框架准入 | 真实源端基线/运行器/sysroot/输入，候选实例执行证据，适用L0–L3与独立审计 | 用目标程序充当源程序；把绑定事件当候选指令覆盖；手工提高通过标志 |

目前所给材料足以实施本轮上述修订，但没有提供能够完成全部ABI、对象域和程序
准入的原生机器/执行事实。本轮不会宣告五项阶段全部完成。源端运行配置仍需要
从原实验记录确定，不能由目标部署计划猜测。缺少的验证消费者也仍需后续开发。

## 证据版本与重新验证

合同报告升级v3；运行报告继续v3、上下文桥继续v1。整个验证器源码清单变化，
必须重新审计部署，并生成本轮上下文和合同报告；旧合同v2不会被直接批准或静默升级。
phase176已经成功的运行证据保留为历史记录。以下各步退出码0表示证据操作完成，
仍须阅读具体完成标志和缺口。

开发环境相关回归：**249 passed，4 skipped**。跳过项涉及真实ptrace、真实Clang、
RISC-V GCC/Clang组合和完整原生翻译前端，均不计为验证通过。GNU ar/GCC/链接
生产者关系有实际工具测试；批次的部分Clang协议测试明确使用模拟边界，不构成
真实跨ISA证明。文档Bash/Python语法检查与`git diff --check`通过。

## 分步实验验证

每步退出码为 0 后再进行下一步；失败时先提供首个失败日志，不检查尚未生成的
result.json。全部输出放在新目录；不要预先 mkdir 工具要创建的输出目录。

### 1. 设置所有变量并获取新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE176_ROOT:?}"
git -C "$REPO" fetch origin phase177-producer-context-scope
export PHASE177_TOOLING="$PREP_ROOT/tooling-phase177"
git -C "$REPO" worktree add --detach "$PHASE177_TOOLING" origin/phase177-producer-context-scope
export PHASE177_ROOT="$(mktemp -d "$PHASE176_ROOT/phase177-XXXXXX")"
: "${PHASE177_ROOT:?}"
export PHASE177_PLAN="$PHASE176_ROOT/deployment/plan.json"
export PHASE177_CLANG="$(command -v clang-10)"
: "${PHASE177_CLANG:?clang-10 unavailable}"
export PYTHONPATH="$PHASE177_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE177_TOOLING" rev-parse HEAD
printf 'PHASE177_ROOT=%s\n' "$PHASE177_ROOT"
ls -lh -- "$PHASE177_PLAN"
```

### 2. 执行相关回归

```bash
python3 -m pytest -q -rs \
  "$PHASE177_TOOLING/pytools/tests/test_native_link_contexts.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_program_scope.py" \
  "$PHASE177_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_binding_stream.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_program_comparison.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE177_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_validation_cli.py" \
  "$PHASE177_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  --basetemp="$PHASE177_ROOT/pytest" > "$PHASE177_ROOT/focused.log" 2>&1
PHASE177_TEST_STATUS=$?
printf 'phase177_test_status=%s\n' "$PHASE177_TEST_STATUS"
cat "$PHASE177_ROOT/focused.log"
```

ptrace 或真实工具链不可用时，测试会明确 skip，不计作真实采集成功。

### 3. 重新审计候选

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "${PHASE177_PLAN:?}" --output "$PHASE177_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE177_ROOT/candidate-audit.log" 2>&1
PHASE177_AUDIT_STATUS=$?
printf 'phase177_audit_status=%s\n' "$PHASE177_AUDIT_STATUS"
cat "$PHASE177_ROOT/candidate-audit.log"
```

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "${PHASE177_PLAN:?}" --input "$PHASE177_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署并检查

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "${PHASE177_PLAN:?}" --audit "$PHASE177_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE177_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE177_ROOT/deployment.log" 2>&1
PHASE177_DEPLOY_STATUS=$?
printf 'phase177_deploy_status=%s\n' "$PHASE177_DEPLOY_STATUS"
cat "$PHASE177_ROOT/deployment.log"
```

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE177_ROOT/deployment/result.json"
```

### 5. 获取新的目标观察

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE177_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE177_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE177_ROOT/observation.log" 2>&1
PHASE177_OBSERVATION_STATUS=$?
printf 'phase177_observation_status=%s\n' "$PHASE177_OBSERVATION_STATUS"
cat "$PHASE177_ROOT/observation.log"
```

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE177_ROOT/observation/result.json"
```

### 6. 采集 v3 运行证据

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" capture-runtime \
  --observation "$PHASE177_ROOT/observation/result.json" \
  --output "$PHASE177_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE177_ROOT/runtime-identity.log" 2>&1
PHASE177_RUNTIME_STATUS=$?
printf 'phase177_runtime_status=%s\n' "$PHASE177_RUNTIME_STATUS"
cat "$PHASE177_ROOT/runtime-identity.log"
```

成功后检查：

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE177_ROOT/runtime-identity/result.json"
```

失败时保留 `runtime-identity/trace/capture.json`，其中记录采集失败原因。

### 7. 按实际记录检查身份关联结果

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['PHASE177_ROOT'])
r=json.loads((root/'runtime-identity/result.json').read_text())
keys=['schemaVersion','bindingEventCount','endpointOccurrenceCount',
      'streamHeaderReplayVerified','fragmentedBindingEventCount',
      'mappedEndpointOccurrencesVerified','unverifiedEndpointOccurrenceCount',
      'diagnosticEndpointMappingComplete','mappingCaptureFailureCount',
      'endpointFailureReasonCounts','metadataCompatibleProviderEvents',
      'metadataFailureReasonCounts','requiredMappedImagesVerified',
      'diagnosticReturnCode','tracedRunReturnCodeMatchesReference',
      'tracedRunStdoutMatchesReference','untracedRuntimeBindingClosureComplete',
      'semanticApproval','productionAcceptanceComplete']
print(json.dumps({k:r[k] for k in keys},indent=2,ensure_ascii=False))
print('unparsedLineCount=',len(r['unparsedLines']))
for row in r['events']:
    if any(not row[s]['diagnosticMappedIdentityVerified'] for s in ('requester','provider')):
        print('firstUnverifiedEvent=',json.dumps(row,ensure_ascii=False));break
PY
```

不要求计数等于历史 301/602，也不预设所有事件的符号元数据必须通过。
若仍有别名未验证，用 `mappingEvidence`、`reasonCodes` 自动追溯 write、epoch
与映像；无需再逐个导出源码宏定义。若只剩元数据问题，检查对应事件的
`requesterSymbolCandidates`、`definitionCandidates` 和 `metadataReasonCodes`。
所有端点关联成功，也不能将 `untracedRuntimeBindingClosureComplete` 改成 true。

### 8. 重新获取上下文和合同输入

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE177_ROOT/deployment/plan.json" \
  --observation "$PHASE177_ROOT/observation/result.json" --clang "$PHASE177_CLANG" \
  --output "$PHASE177_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE177_ROOT/context-bridge.log" 2>&1
PHASE177_CONTEXT_STATUS=$?
printf 'phase177_context_status=%s\n' "$PHASE177_CONTEXT_STATUS"
cat "$PHASE177_ROOT/context-bridge.log"
```

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" inspect-contracts \
  --context "$PHASE177_ROOT/context-bridge/result.json" \
  --observation "$PHASE177_ROOT/observation/result.json" --clang "$PHASE177_CLANG" \
  --runtime "$PHASE177_ROOT/runtime-identity/result.json" \
  --output "$PHASE177_ROOT/contracts-with-runtime" --timeout-seconds 600 \
  > "$PHASE177_ROOT/contracts-with-runtime.log" 2>&1
PHASE177_CONTRACT_STATUS=$?
printf 'phase177_contract_status=%s\n' "$PHASE177_CONTRACT_STATUS"
cat "$PHASE177_ROOT/contracts-with-runtime.log"
```

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE177_ROOT/contracts-with-runtime/result.json"
```

如果运行采集失败，仍可省略 `--runtime` 采集静态合同；这时状态应为
`not-acquired`，不能把零计数当作“无缺口”。

### 9. 获取自动盘点以安排后续证明

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE177_ROOT'])/'contracts-with-runtime/result.json'
r=json.loads(p.read_text())
print(json.dumps({'stages':r['stages'],'coverageInventory':r['coverageInventory']},
                 indent=2,ensure_ascii=False))
PY
```

请提供步骤 7 的摘要与本步骤的结果。没有任何阶段能仅凭 `evidenceOperationComplete`
或退出码 0 宣告语义完成。

### 10. 有限源目标进程比较

复用 [phase174 步骤 8](phase174-runtime-contract-evidence.md#8-明确源端运行配置后进行有限程序观察比较)
的既有比较功能，但所有工具、部署、计划及输出路径使用本次 `PHASE177_TOOLING`
和 `PHASE177_ROOT`；不要引用旧部署比较计划。
必须先从原源端基线记录确定实际 RISC-V 可执行文件、运行器、sysroot、参数、环境
与工作目录，不能猜测或用目标程序充当源端。

成功比较后可用本轮 `refine-contracts --input
"$PHASE177_ROOT/contracts-with-runtime/result.json" --comparison <本轮比较结果>
--output <全新目录>` 关联。有限观察比较继续不批准内部对象域、源执行机制或 L1。

### 11. 按预算采集依赖的原生上下文

步骤8成功后，可自动采集第一批4个C上下文。程序从生产者图选择，不需要手动指定
源码路径。每个上下文沿捕获的原生参数重新预处理，再由Clang检查；父回执可复用
时先验证再复用。输出为全新目录。每个上下文的超时预算由参数给出。

```bash
: "${PHASE177_ROOT:?}" "${PHASE177_TOOLING:?}" "${PHASE177_CLANG:?}"
export PHASE177_BATCH_PARENT="$(mktemp -d "$PHASE177_ROOT/context-batch-XXXXXX")"
: "${PHASE177_BATCH_PARENT:?}"
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" acquire-context-batch \
  --contracts "$PHASE177_ROOT/contracts-with-runtime/result.json" \
  --clang "$PHASE177_CLANG" --start-index 0 --count 4 --timeout-seconds 600 \
  --output "$PHASE177_BATCH_PARENT/evidence" \
  > "$PHASE177_BATCH_PARENT/acquisition.log" 2>&1
PHASE177_BATCH_STATUS=$?
printf 'phase177_batch_status=%s\n' "$PHASE177_BATCH_STATUS"
cat "$PHASE177_BATCH_PARENT/acquisition.log"
```

成功后检查：

```bash
python3 "$PHASE177_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE177_BATCH_PARENT/evidence/result.json"
```

`selectedContextAcquisitionComplete`只说明本批次的采集；读取`nextIndex`和
`totalContextCount`，后续可用新的目录从`nextIndex`继续。默认不一次处理全部
数百个上下文。不可检查或非x86-64上下文明确列为未采集；编译/检查失败时保留
对应`context-00000N/run-status.json`，先分析首个失败，不修改参数来压过它。

批次不会反向修改原合同或清除ABI/对象义务。其回执是后续验证消费者的输入，
不是采集完成即语义通过。也不能仅因某个上下文不在局部已知调用图中就永久排除。

### 12. 提供精简的新证据摘要

下面只导出结构化摘要，不打印整份AST。原完整报告仍保留用于按身份追溯。

```bash
python3 - <<'PY' > "$PHASE177_ROOT/phase177-summary.json"
import json,os
from pathlib import Path
from collections import Counter
root=Path(os.environ['PHASE177_ROOT'])
r=json.loads((root/'contracts-with-runtime/result.json').read_text())
p=r['producerContextClosure'];s=r['programScope']
scope={}
for name,row in s['localScopes'].items():
    scope[name]={'rootAstPaths':row['rootAstPaths'],'rootAuthority':row['rootAuthority'],
        'visitedFunctionCount':len(row['visitedFunctionAstPaths']),
        'visitedCallCount':len(row['visitedCallEvidenceIdentities']),
        'terminalCallClassCounts':dict(Counter(v['classification'] for v in row['terminalCallObligations'])),
        'unvisitedFunctionCount':len(row['unvisitedFunctionAstPaths']),
        'unvisitedFunctionsProvedUnreachable':row['unvisitedFunctionsProvedUnreachable']}
summary={'schemaVersion':r['schemaVersion'],'contractEvidenceIdentity':r['contractEvidenceIdentity'],
    'stages':r['stages'],'entryInputGaps':r['entryInputGaps'],
    'producerSummary':{'capturedProducerClosureComplete':p['capturedProducerClosureComplete'],
        'nodeCount':len(p['nodes']),'compileContextCount':len(p['compileContexts']),
        'gapReasonCounts':dict(Counter(g['reasonCode'] for g in p['inputGaps'])),
        'entryOccurrences':p['entryOccurrences'],'deployedReplacements':p['deployedReplacements'],
        'actualArchiveExtractionSelectionVerified':p['actualArchiveExtractionSelectionVerified'],
        'implicitDriverDependenciesIncluded':p['implicitDriverDependenciesIncluded']},
    'scopeSummary':scope,'scopeGaps':s['scopeGaps'],
    'candidatePICArguments':s['candidatePICArguments'],'producerPICArguments':s['producerPICArguments'],
    'explicitPICArgumentsEqual':s['explicitPICArgumentsEqual'],
    'constantInitializerCounts':{name:sum(v['inspectionTypedConstantInitializerVerified'] for v in rows)
        for name,rows in r['constantInitializerEvidence'].items()},
    'semanticApproval':r['semanticApproval'],'productionAcceptanceComplete':r['productionAcceptanceComplete']}
print(json.dumps(summary,indent=2,ensure_ascii=False))
PY
```

优先提供`focused.log`、`contracts-with-runtime.log`、`phase177-summary.json`和
批次`acquisition.log`/`evidence/result.json`。如有失败先提供首个失败日志。
通过该摘要可以分别判断归档生产链、库/对象生产者、C上下文采集以及局部范围是否
取得预期进展，不能把其中任何一项替代完整五项程序级合同。


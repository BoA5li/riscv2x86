# Phase181：受限 API 实验、实例语句观察与原验证器准入

父版本：phase180-response-entry-validation，远端 c6b934db1f68aae4f2b5c3c57d7a046782f81e6f。
本分支包含 phase180 的全部修订，可在一次新实验中联合验证两轮改动。

**本轮不是全部剩余缺口的闭合证书。** 它补充可执行的输入构造、声明核验、API
差分、实例语句观察及原调度器连接。完整机器 ABI、函数内部对象访问合法性、自然
运行的规范代码指令覆盖、外部依赖行为及独立程序级审计仍未全部实现/证明。

## 实装与接受范围

| 实现 | 实际验证 | 不可据此推出 |
| --- | --- | --- |
| native_api_contract | 从编译器声明/唯一 typedef 图解析固定参数 LP64 标量和一层指针；跨三端核对接口；变参、浮点、聚合、歧义别名和未知 ABI 属性拒绝 | 所有 ABI 类型受支持；机器代码已保存寄存器/遵守栈/异常合同 |
| native_api_experiment | 在源/候选原始预处理单元中追加类型静态断言并实际编译；生成相同输入驱动；显式 RV64 库和启动器；源 ELF 浮点 ABI 从真实 source.o 导出；复用原 L1 字节比较 | Inspector 的 AST 等于 native 编译器 ABI；一次输出相等等于整个 GMP 语义等价 |
| 对象/输入合同 | 强制数组全初始化、对齐、有效偏移、同对象别名及调用期间生命周期；检查范围、容量、同对象、区间不交和更强对齐约束；保留前置条件的声明来源 | 输入初始化意味着函数内部所有访问均合法；可自动推导所有库函数前置条件 |
| native_statement_probe | 以每个 instanceBindingIdentity 对应的已审计 replacement 字节范围插入进入/完成计数；独立生成变体、重链接和运行；保留未命中实例 | 函数入口等于片段执行；带插桩变体等于规范二进制；微架构意图保留 |
| native_l0_materialization | 用原生成器为完整候选单元生成真实18单元矩阵和主产物；保持归档/对象原链接次序；按操作冻结两端环境 | 旧 O2 产物可冒充 GCC-O0 基准；删掉 Clang/优化级别/消毒器来通过 |
| native_framework_admission | 导出真实局部证明绑定的原 TranslationArtifact/ProgramArtifact；调用原 run_translation_validation 和注册运行器；原 L0 只写隔离副本；区分调度器调用、运行器调用、原生合同阻挡和验证结果 | 创建空 registry/命令退出0意味着通过；缺少 ABI/对象合同也能进入语义接受；已实现全部 L2/L3 证据生产者 |
| 原合同回接 | refine/check 消费新证据并核对基础合同身份；inputs v5；摘要显示真实运行器状态和受限子目标 | 修改五个整体阶段的通过条件；用局部子目标覆盖全局未知 |

所有解析依据编译器结构、类型和真实身份，不匹配 GMP 函数名、目录名或某个固定
实例索引。支持范围有限时明确拒绝或给出 inconclusive。

数组总元素上限65536、用例256、对象/参数32、前置条件64且总表达式节点1024。
只有完整输出协议、正常终止及逐字节比较一致，受限 API 比较才 verified；两个空
日志不能通过。预处理单元和原候选文件保持不变。

NoThrowAttr/NonNullAttr 被保留并按 ABI 中立属性处理；所有生成指针均指向活跃且
初始化的数组。此处理不证明函数无异常/无保护失败。native 端允许使用真实头文件
原型关联汇编提供者，但它仍缺少汇编行为合同，不能当成已经验证的 C 函数体。

## 先联合复验两轮已有工作链

即使尚未执行 phase180，也可从现存 PHASE179_ROOT 开始。不要复用旧 verifier
清单批准新源码；以下重新审计/部署。失败时保留首个日志，不检查不存在的结果。

### 1. 固定变量和新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE179_ROOT:?}"
git -C "$REPO" fetch origin phase181-native-api-admission
export PHASE181_TOOLING="$PREP_ROOT/tooling-phase181"
git -C "$REPO" worktree add --detach "$PHASE181_TOOLING" origin/phase181-native-api-admission
export PHASE181_ROOT="$(mktemp -d "$PHASE179_ROOT/phase181-XXXXXX")"
: "${PHASE181_ROOT:?}"
export PHASE181_PLAN="$PHASE179_ROOT/deployment/plan.json"
export PHASE181_CLANG="$(command -v clang-10)"
: "${PHASE181_CLANG:?}"
export PYTHONPATH="$PHASE181_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE181_CLI="$PHASE181_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE181_TOOLING" rev-parse HEAD
printf 'PHASE181_ROOT=%s\n' "$PHASE181_ROOT"
```

### 2. 回归

```bash
python3 -m pytest -q -rs \
  "$PHASE181_TOOLING/pytools/tests/test_gnu_response_files.py" \
  "$PHASE181_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE181_TOOLING/pytools/tests/test_project_build_capture.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_l0_materialization.py" \
  "$PHASE181_TOOLING/pytools/tests/test_l0_build_matrix.py" \
  "$PHASE181_TOOLING/pytools/tests/test_mechanism_source_dso_l0.py" \
  "$PHASE181_TOOLING/pytools/tests/test_validation_configuration.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_api_contract.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_api_experiment.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_statement_probe.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_framework_admission.py" \
  "$PHASE181_TOOLING/pytools/tests/test_translation_validation.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_entry_probe.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_capture_scope.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_link_contexts.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_context_resolution.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_priority_contexts.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE181_TOOLING/pytools/tests/test_native_validation_cli.py" \
  --basetemp="$PHASE181_ROOT/pytest" > "$PHASE181_ROOT/focused.log" 2>&1
PHASE181_TEST_STATUS=$?
printf 'test_status=%s\n' "$PHASE181_TEST_STATUS"
cat "$PHASE181_ROOT/focused.log"
```

### 3. 审计

```bash
python3 "$PHASE181_CLI" audit-candidate --plan "$PHASE181_PLAN" \
  --output "$PHASE181_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE181_ROOT/audit.log" 2>&1
PHASE181_STATUS=$?
printf 'audit_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/audit.log"
```

```bash
python3 "$PHASE181_CLI" check-audit --plan "$PHASE181_PLAN" \
  --input "$PHASE181_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署

```bash
python3 "$PHASE181_CLI" deploy --plan "$PHASE181_PLAN" \
  --audit "$PHASE181_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE181_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE181_ROOT/deployment.log" 2>&1
PHASE181_STATUS=$?
printf 'deploy_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/deployment.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/deployment/result.json"
```

### 5. 运行与诊断映射

```bash
python3 "$PHASE181_CLI" observe --input "$PHASE181_ROOT/deployment/result.json" \
  --diagnostic --output "$PHASE181_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE181_ROOT/observation.log" 2>&1
PHASE181_STATUS=$?
printf 'observe_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/observation.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/observation/result.json"
```

```bash
python3 "$PHASE181_CLI" capture-runtime --observation "$PHASE181_ROOT/observation/result.json" \
  --output "$PHASE181_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE181_ROOT/runtime.log" 2>&1
PHASE181_STATUS=$?
printf 'runtime_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/runtime.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/runtime-identity/result.json"
```

### 6. 复用原生目标采集，产生本轮上下文桥

```bash
export PHASE181_REUSE_TARGET="$(python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE179_ROOT'])/'context-bridge/inputs.json'
print(json.loads(p.read_text())['targetReceipt']['path'])
PY
)"
: "${PHASE181_REUSE_TARGET:?}"
python3 "$PHASE181_CLI" inspect-context --plan "$PHASE181_ROOT/deployment/plan.json" \
  --observation "$PHASE181_ROOT/observation/result.json" --clang "$PHASE181_CLANG" \
  --reuse-native-input "$PHASE181_REUSE_TARGET" \
  --output "$PHASE181_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE181_ROOT/context.log" 2>&1
PHASE181_STATUS=$?
printf 'context_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/context.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/context-bridge/result.json"
```

### 7. 复用入口回执，生成全阶段基础合同

```bash
python3 - <<'PY' > "$PHASE181_ROOT/contracts.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE181_ROOT'])
old=json.loads((Path(os.environ['PHASE179_ROOT'])/'contracts-with-runtime/inputs.json').read_text())
cmd=[sys.executable,os.environ['PHASE181_CLI'],'inspect-contracts',
 '--context',str(root/'context-bridge/result.json'),'--observation',str(root/'observation/result.json'),
 '--runtime',str(root/'runtime-identity/result.json'),'--clang',os.environ['PHASE181_CLANG'],
 '--output',str(root/'contracts-with-runtime'),'--timeout-seconds','600']
for row in old['entryReceipts']:cmd+=['--reuse-entry-receipt',row['path']]
raise SystemExit(subprocess.call(cmd))
PY
PHASE181_STATUS=$?
printf 'contracts_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/contracts.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/contracts-with-runtime/result.json"
```

重点检查新增captureScopes里的真实阶段、归档producerBound及archiveProducerStages。
如果capturedProducerClosureComplete仍false，读具体reason；不将阶段遗漏假设当既定事实。
即使变true，也不能宣称ABI或完整链接闭包已通过。

### 8. 按上下文身份迁移已有首批回执

跨阶段恢复可能改变列表索引；不能把旧索引直接套用到新合同。以下按完整contextIdentity
定位新索引，复用之前的回执。缺失或变化会停止，不静默接受不兼容输入。

```bash
python3 - <<'PY' > "$PHASE181_ROOT/seed-batch.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE181_ROOT'])
base=root/'contracts-with-runtime/result.json'
report=json.loads(base.read_text())
positions={c['contextIdentity']:i for i,c in enumerate(report['producerContextClosure']['compileContexts'])}
old_rows=[]
for name in ('seed-batch','priority-batch'):
 file=Path(os.environ['PHASE179_ROOT'])/name/'result.json'
 if file.is_file():old_rows+=json.loads(file.read_text())['rows']
old={r['contextIdentity']:r for r in old_rows}
cmd=[sys.executable,os.environ['PHASE181_CLI'],'acquire-context-batch','--contracts',str(base),
 '--clang',os.environ['PHASE181_CLANG'],'--output',str(root/'seed-batch'),'--timeout-seconds','600']
for row in old.values():
 if not row['nativeInputAcquired']:continue
 cid=row['contextIdentity']
 if cid not in positions:raise ValueError('OLD_CONTEXT_NOT_PRESENT_IN_NEW_PRODUCER_GRAPH:'+cid)
 cmd+=['--context-index',str(positions[cid]),'--reuse-receipt',row['receipt']['path']]
if '--context-index' not in cmd:raise ValueError('NO_VALIDATED_SEED_CONTEXT')
raise SystemExit(subprocess.call(cmd))
PY
PHASE181_STATUS=$?
printf 'seed_batch_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/seed-batch.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/seed-batch/result.json"
```

### 9. 解析现有上下文并产生新的采集优先级

```bash
python3 "$PHASE181_CLI" resolve-contexts \
  --contracts "$PHASE181_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE181_ROOT/seed-batch/result.json" \
  --output "$PHASE181_ROOT/seed-resolution" > "$PHASE181_ROOT/seed-resolution.log" 2>&1
PHASE181_STATUS=$?
printf 'seed_resolution_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/seed-resolution.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/seed-resolution/result.json"
```

### 10. 独立重建并核验观察到的归档贡献

```bash
python3 "$PHASE181_CLI" audit-archive-selection \
  --deployment "$PHASE181_ROOT/deployment/result.json" \
  --output "$PHASE181_ROOT/archive-audit" --timeout-seconds 600 \
  > "$PHASE181_ROOT/archive-audit.log" 2>&1
PHASE181_STATUS=$?
printf 'archive_audit_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/archive-audit.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/archive-audit/result.json"
```

independentObservedArchiveContributionsVerified只对应观察到且可唯一归属的成员贡献。
没有归档、没有受支持贡献或不能复现时不能通过空集得到true。完整抽取闭包仍独立。

### 11. 自动采集下一批相关C上下文

```bash
python3 "$PHASE181_CLI" acquire-priority-contexts \
  --resolution "$PHASE181_ROOT/seed-resolution/result.json" \
  --clang "$PHASE181_CLANG" --count 4 --timeout-seconds 600 \
  --output "$PHASE181_ROOT/priority-batch" > "$PHASE181_ROOT/priority-batch.log" 2>&1
PHASE181_STATUS=$?
printf 'priority_batch_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/priority-batch.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/priority-batch/result.json"
```

仅处理最新报告中的优先索引，不复用旧的102/156等数字。若明确报告
PRIORITY_CONTEXT_NO_C_CONTEXT_PENDING，则没有可调度的C上下文；这不是语义通过。
这种情况下下一步只传seed批次，继续处理其他义务。

### 12. 累积上下文，接回原合同工作链

若第11步成功：

```bash
python3 "$PHASE181_CLI" resolve-contexts \
  --contracts "$PHASE181_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE181_ROOT/seed-batch/result.json" \
  --context-batch "$PHASE181_ROOT/priority-batch/result.json" \
  --output "$PHASE181_ROOT/context-resolution" > "$PHASE181_ROOT/resolution.log" 2>&1
PHASE181_STATUS=$?
printf 'resolution_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/resolution.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/context-resolution/result.json"
```

```bash
python3 "$PHASE181_CLI" refine-contracts \
  --input "$PHASE181_ROOT/contracts-with-runtime/result.json" \
  --context-resolution "$PHASE181_ROOT/context-resolution/result.json" \
  --archive-audit "$PHASE181_ROOT/archive-audit/result.json" \
  --output "$PHASE181_ROOT/contracts-resolved" > "$PHASE181_ROOT/refinement.log" 2>&1
PHASE181_STATUS=$?
printf 'refine_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/refinement.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/contracts-resolved/result.json"
```

### 13. 自动导出最终合同摘要

```bash
python3 "$PHASE181_CLI" summarize-contracts \
  --input "$PHASE181_ROOT/contracts-resolved/result.json" \
  --output "$PHASE181_ROOT/phase181-summary.json"
```

摘要为便于分析的派生视图，不是独立接受证书。stages和validationProgress均取最终
合同，避免旧摘要只显示基础合同。优先提供 focused.log、contracts.log、archive-audit.log、
priority-batch.log、refinement.log、phase181-summary.json；失败只需先提供首个失败日志。

### 14. 获取候选函数入口的实际观察

```bash
python3 "$PHASE181_CLI" capture-entry \
  --contracts "$PHASE181_ROOT/contracts-resolved/result.json" \
  --output "$PHASE181_ROOT/function-entry" --timeout-seconds 600 \
  > "$PHASE181_ROOT/function-entry.log" 2>&1
PHASE181_STATUS=$?
printf 'entry_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/function-entry.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/function-entry/result.json"
```

若权限/内核能力不足，查看 function-entry/trace/capture.json 的 failureReason；不能
将跳过或失败当成覆盖成功。若某个函数未进入，命令可以成功完成采集，但
candidateFunctionEntriesObserved 为 false。若编译器没有提供 linkerName 或定义不能
唯一归属，定位阶段直接拒绝，不根据函数名文本猜测地址。

### 15. 将入口观察接回原合同

```bash
python3 "$PHASE181_CLI" refine-contracts \
  --input "$PHASE181_ROOT/contracts-resolved/result.json" \
  --entry-coverage "$PHASE181_ROOT/function-entry/result.json" \
  --output "$PHASE181_ROOT/contracts-with-entry" \
  > "$PHASE181_ROOT/entry-refinement.log" 2>&1
PHASE181_STATUS=$?
printf 'entry_refinement_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/entry-refinement.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/contracts-with-entry/result.json"
```

```bash
python3 "$PHASE181_CLI" summarize-contracts \
  --input "$PHASE181_ROOT/contracts-with-entry/result.json" \
  --output "$PHASE181_ROOT/phase181-entry-summary.json"
```

验收：新子目标 instrumented-candidate-function-entry 仅在全部选定函数观察到入口时
verified；candidateInstructionExecutionCoverageVerified、nativeAbiClosureVerified、
legalObjectDomainVerified、untracedRunCoverageVerified 仍为 false。合同五个整体阶段
必须保持自身证据决定的状态，不能因新增子目标而整体通过。

## 16. 生成实际声明和输入域模板

前面步骤全部通过后，固定本次基础合同。所有新证据都使用这个相同身份，最后一起
refine；不要从已经消费 API/语句证据的合同再次递归生成同一类证据。

```bash
export PHASE181_BASE="$PHASE181_ROOT/contracts-with-entry/result.json"
: "${PHASE181_BASE:?}"
python3 "$PHASE181_CLI" prepare-api --contracts "$PHASE181_BASE" \
  --output "$PHASE181_ROOT/api-plan.json"
```

api-plan.json 的 functions 包含真实 functionAstPath、functionEvidenceIdentity、
三端核对后的接口、编译器范围绑定的源函数文本，以及绑定基础合同的 domainTemplate。
不支持的函数保留 unsupportedReason，不会从实验分母中静默移除。

**必须审定真实输入前置条件。** 模板 cases=[] 故意不可执行；工具不会按参数名称猜测
长度、指针角色或 GMP 对象布局。复制选定函数的 domainTemplate 为 api-domain.json，
填写其中 domain.cases 和 preconditions。不要删除顶层合同/函数身份绑定。

下面只说明通用 DSL，**不是当前 GMP 的有效域证书**。若实际接口是
`unsigned long transform(unsigned long *, const unsigned long *, long)`，一个示例域为：

```json
{
  "schemaVersion": "riscv2x86.native-api-domain.v1",
  "claimScope": "bounded-api-under-declared-preconditions",
  "preconditions": [
    {"gt": [{"argument": 2}, {"constant": 0}]},
    {"ge": [{"remainingElements": 0}, {"argument": 2}]},
    {"ge": [{"remainingElements": 1}, {"argument": 2}]},
    {"disjoint": [0, 1, {"argument": 2}, {"argument": 2}]}
  ],
  "cases": [{
    "objects": [
      {"id": "destination", "type": "unsigned long", "alignment": 16, "values": [0, 0]},
      {"id": "source", "type": "unsigned long", "alignment": 16, "values": [2, 3]}
    ],
    "arguments": [
      {"object": "destination", "offsetElements": 0},
      {"object": "source", "offsetElements": 0},
      {"integer": 2}
    ]
  }]
}
```

该对象是 domainTemplate.domain 的内容，不能替代带身份的外层模板。参数索引从0
开始；两个参数引用同一对象 ID 才表达别名。支持 add/multiply、eq/ne/lt/le/gt/ge、
sameObject、disjoint 和 aligned。输入域针对本次接口，但解析/验证算法不依赖项目。

当前无法从已有摘要证明所有 GMP 前置条件，因此不能自动填一个“看起来合理”的
域并称其合法。若需要协助审定，只需提供本次 api-plan.json；无需重新逐文件导出
之前的大批日志。

## 17. 执行双端 API 验证

SOURCE_GMP_LIBRARY 必须是此前源端构建的真实 RV64 库（普通 .a 或 ELF .so），
不是 x86 目标库。启动器及参数明确提供，不自动猜测 sysroot。

```bash
: "${SOURCE_GMP_LIBRARY:?请设置已验证源端库的实际路径}"
export PHASE181_QEMU="$(command -v qemu-riscv64)"
: "${PHASE181_QEMU:?}"
ls -lh -- "$SOURCE_GMP_LIBRARY" "$PHASE181_ROOT/api-domain.json"
```

若原源端基线使用了 QEMU 的 `-L`，应沿用其已核验路径，并添加
`--launcher-arg=-L --launcher-arg="$SOURCE_SYSROOT"`；不要猜路径或靠宿主加载 RV64。
以下是不需要额外启动参数时的命令：

```bash
python3 "$PHASE181_CLI" run-api --contracts "$PHASE181_BASE" \
  --domain "$PHASE181_ROOT/api-domain.json" \
  --source-library "$SOURCE_GMP_LIBRARY" --source-launcher "$PHASE181_QEMU" \
  --output "$PHASE181_ROOT/api" --timeout-seconds 600 \
  > "$PHASE181_ROOT/api.log" 2>&1
PHASE181_STATUS=$?
printf 'api_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/api.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/api/result.json"
```

重点核查 processObservationStatus、harnessObservationProtocolComplete 和各阶段原始
日志。即使受限 API 为 verified，nativeAbiClosureVerified、legalObjectDomainVerified
仍不能据此升级。保护失败、非正常终止和不完整协议保留为未通过/无法判定。

## 18. 获取每个翻译语句的进入/完成记录

```bash
python3 "$PHASE181_CLI" capture-statements \
  --api-experiment "$PHASE181_ROOT/api/result.json" \
  --output "$PHASE181_ROOT/statements" --timeout-seconds 600 \
  > "$PHASE181_ROOT/statements.log" 2>&1
PHASE181_STATUS=$?
printf 'statements_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/statements.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/statements/result.json"
```

每个实例都必须有完整事件。进入次数大于完成次数、未命中、重复/非法事件、输出
变化等不能闭合。这里覆盖候选的全部已绑定编辑，不会仅保留本次 API 触及的实例。
canonicalInstructionCoverageVerified 和 untracedRunCoverageVerified 仍为 false。

## 19. 真正生成原 L0 输入，再调用原调度器

这一步可以在 API 输入域尚未审定时独立进行，使用同一个 PHASE181_BASE。
先导出真实局部证明绑定的原 TranslationArtifact：

```bash
python3 "$PHASE181_CLI" export-framework --contracts "$PHASE181_BASE" \
  --output "$PHASE181_ROOT/framework-artifacts.json"
```

旧部署 O2 产物不一定等于原矩阵的 gcc-O0-none 基准，不能仅复制旧 digest 填进去。
下面通过原 build_l0_reference_manifest，实际重新编译源单元和候选单元，并把候选
对象放回捕获库链接命令的原位置。其它对象/归档保持身份与次序；参数环境按两端
各自捕获值执行，不改全局 os.environ。

为首次共享单元 BUILD 验证选择一个真实实例作原框架绑定锚：

```bash
export PHASE181_INSTANCE="$(python3 - <<'PY'
import json,os
from pathlib import Path
value=json.loads((Path(os.environ['PHASE181_ROOT'])/'framework-artifacts.json').read_text())
if not value['artifacts']:raise ValueError('NO_NATIVE_PROOF_ARTIFACT')
print(value['artifacts'][0]['instanceBindingIdentity'])
PY
)"
: "${PHASE181_INSTANCE:?}"
```

这里编译的是整个候选单元，选择锚不删除其它编辑，也不代表其它实例的 L2 接受。

```bash
python3 "$PHASE181_CLI" materialize-native-l0 --contracts "$PHASE181_BASE" \
  --instance "$PHASE181_INSTANCE" --output "$PHASE181_ROOT/l0-inputs" \
  --timeout-seconds 600 > "$PHASE181_ROOT/l0-materialization.log" 2>&1
PHASE181_STATUS=$?
printf 'l0_materialization_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/l0-materialization.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/l0-inputs/result.json"
```

必须有 GCC、Clang、三个优化级别以及 none/ASan/UBSan 的全部真实产物。缺工具或
某单元失败，保留失败，不伪造 reference。生成 reference 不等于验证通过：还需
原运行器独立重建、核对产物、ELF ABI 和实际加载。

为初次 BUILD 运行自动生成真实计划、环境描述和原运行器注册配置。QEMU 用实际
路径探测并封存，但 BUILD 本身不执行源程序；source-isa 是本实验声明的源环境，
应与原源端编译/执行配置一致，当前示例沿用 RV64GC：

```bash
export PHASE181_QEMU="$(command -v qemu-riscv64)"
: "${PHASE181_QEMU:?}"
python3 "$PHASE181_CLI" prepare-native-l0-request \
  --native-build "$PHASE181_ROOT/l0-inputs/result.json" \
  --framework-output "$PHASE181_ROOT/framework" --qemu "$PHASE181_QEMU" \
  --source-isa rv64gc --output "$PHASE181_ROOT/framework-request.json"
```

```bash
python3 "$PHASE181_CLI" run-framework --contracts "$PHASE181_BASE" \
  --request "$PHASE181_ROOT/framework-request.json" \
  --output "$PHASE181_ROOT/framework" \
  > "$PHASE181_ROOT/framework.log" 2>&1
PHASE181_STATUS=$?
printf 'framework_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/framework.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/framework/result.json"
```

原运行器只重建隔离副本；reference 和旧部署保持固定。若 L0 为 verified，隔离产物
必须仍匹配原期望 digest。矩阵保持原18单元、警告、ABI、加载与摘要要求。

originalFrameworkInvoked=true 代表调用了原调度器；executedOriginalValidatorLevels
才说明哪些原运行器真正被调用。本次自动计划是 BUILD，成功只表示 L0，不表示
L1/L2/L3 已通过。摘要会记录 L0 实际状态，未请求的层继续 not_run。

如后续已有真实 L1–L3 运行器/provider，可基于原公开请求 schema 显式配置更高
profile；不能只改 profile 而编造运行器/证据。需要的 native ABI、对象、输出合同
未闭合时仍阻挡语义准入，且会区分 not_run 和 admissionStatus。

check 核验输入、原聚合和准入重派生；不等于独立重跑各层或完成程序级审计。
完整矩阵、机器 ABI、对象域或实例证据缺少时，保留 failed/inconclusive。此轮并未
使全部五阶段可自动 verified。

## 20. 一次回接本次可获得的实验结果

有 API 和语句结果后即可回接这两个受限子目标。只有第19步真的生成可 check 的结果，
才额外加入 `--framework-execution "$PHASE181_ROOT/framework/result.json"`。

```bash
python3 "$PHASE181_CLI" refine-contracts --input "$PHASE181_BASE" \
  --api-experiment "$PHASE181_ROOT/api/result.json" \
  --statement-probe "$PHASE181_ROOT/statements/result.json" \
  --output "$PHASE181_ROOT/contracts-experiments" \
  > "$PHASE181_ROOT/experiments-refinement.log" 2>&1
PHASE181_STATUS=$?
printf 'refinement_status=%s\n' "$PHASE181_STATUS"
cat "$PHASE181_ROOT/experiments-refinement.log"
```

```bash
python3 "$PHASE181_CLI" check --input "$PHASE181_ROOT/contracts-experiments/result.json"
```

```bash
python3 "$PHASE181_CLI" summarize-contracts \
  --input "$PHASE181_ROOT/contracts-experiments/result.json" \
  --output "$PHASE181_ROOT/phase181-experiment-summary.json"
```

## 响应文件修订的真实 GMP 复验

phase180 中缺失的历史 @文件不会被补回。还需从 configure 开始新捕获，使用
[phase180说明](phase180-response-entry-validation.md) B部分的 prepare-target/run/check-run
步骤。将其中 PHASE180_TOOLING、PHASE180_ROOT 全部换为本次 PHASE181_TOOLING、
PHASE181_ROOT；不再创建 phase180 worktree。新捕获与旧部署是不同实验状态，不能
将新 records.json 拼接到旧部署计划。后续部署必须重新准备并审计。

## 回传与完成判断

先返回 focused.log。尚未审定输入时，下一份只需要 api-plan.json。完成 API 后返回
api.log、api/result.json；完成实例观察后返回 statements/result.json；原调度器运行后
返回 framework/result.json，最后返回 phase181-experiment-summary.json。失败只先提供
首个失败日志。所有路径均以本次打印的 PHASE181_ROOT 为根。

必须分别判断“代码回归通过”“受限 API/插桩观察有效”“五阶段合同闭合”和“原
L0–L3 通过”。它们是不同结论；本轮不能将前两项写成后两项。

## ABI 依据

固定整数/指针槽位依据 [RISC-V psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/)
及 [AMD64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex)。
这些是要求的布局，不是机器代码已满足全部 ABI 的证明。

## 本地联合回归记录

本分支冻结代码后的联合回归：**301 passed，5 skipped，312.58 秒**。
原始日志与机器可读摘要保存在 experiment/baselines/phase181/。
其中2项因 ptrace 不可用跳过，3项因缺少真实 RISC-V GCC/QEMU 跳过；后者包括
真实跨架构 API 实验和18单元 L0 矩阵。跳过不记为通过。本机未执行真实 GMP
实验，也未证明完整 L0–L3 接受。必须按本文步骤在实验容器重新验证。

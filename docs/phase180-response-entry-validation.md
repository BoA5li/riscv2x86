# Phase180：响应文件生产证据与候选函数入口观察

基于远端 phase179-cross-stage-validation（4251eb91f5a3f5ba375ede71116b6438cc688455）。
本轮实装两个必要子能力，并把入口观察接回原合同 refine/check。**没有完成全部
ABI、对象域、内联实例覆盖和 L0–L3 准入**。不要将本轮命令成功理解为完整 GMP
翻译评估通过。

## 修订原理、代码位置与边界

| 缺口 | 实际修订 | 接受条件与限制 |
| --- | --- | --- |
| GNU ar/ranlib 的 @响应文件不能建立生产链 | gnu_response_files、project_archive_provenance、project_build_capture：捕获时读取并封存原始字节；按 GNU/libiberty 的平衡引号、反斜杠和 ASCII 空白规则展开；嵌套路径基于调用目录；原命令及展开命令均保留 | 支持 UTF-8、无 NUL、平衡引号的严格子集；循环、缺失文件、非普通文件、预算超限不能取得权威。深度16、128文件、总4MiB、65536参数上限。不是 shell 解析 |
| 捕获后工具可能再次读取已变化的响应文件 | 实际归档工具使用冻结的展开参数执行；输出捕获也使用展开参数；解析器源码摘要加入 capture 配置 | 这是显式冻结执行模式，回执记录 executionMode；完整成员转换、顺序、摘要、生产/消费时序仍须通过原验证 |
| 不知道哪个归档操作真正阻塞 | select 返回 blockingActionIdentity、blockingArguments、blockingDirectory | 不跳过名为 conftest 的操作；不把旧目录里的同名响应文件当历史内容 |
| 只有链接/映射信息，没有候选函数实际进入记录 | native_entry_probe 复用 native_process_identity 的受限 ptrace；从编译器声明根、唯一强定义链接归属、最终 ELF 符号及实际映射定位入口，安装单次断点，命中后恢复字节并回退 PC | Linux x86-64、单进程、64个目标上限、私有不可写可执行映射；复用原时间/输出/映像/停止次数预算；别名、歧义加载、异常 trap、映射变更不能批准 |
| 采集记录不能只靠自报成功 | 独立从封存 ELF/映射重新计算地址与原始字节，核对 PC、epoch、停止顺序、输出摘要、执行参数和完整父合同 | 记录命中时原始寄存器，不将其解码为已证明的 ABI 值或合法指针 |
| 新证据孤立在旧工作链之外 | refine-contracts --entry-coverage；inputs v4 封存依赖，check 重派生；summary 显示新的受限子目标 | 必须与生成入口证据时的完整基础合同身份一致；不能同时改变其基础义务后继续沿用。五个整体阶段不会因此升级 |

入口观察执行沿用已核验自然运行的 argv/env，但在新的证据目录运行并明确记录工作
目录变化。插桩改变执行环境，返回码/标准输出/标准错误比较仅为诊断，不能推出自然
运行等价。即使全部候选函数入口被观察到，也不能推出其中所有内联汇编实例被执行。

## 必须保留的剩余修订

| 必要能力 | 代码入口 | 后续实现要求 |
| --- | --- | --- |
| 真实选择与接口 | native_context_resolution、native_contract_evidence、function_abi_sidecar、register_call_abi | 将实际提供者与源/候选/原生声明、编译参数及机器调用约定关联；补齐真正需要的 x86/RV64 参数分类、返回、保存寄存器、栈、变参和布局事实。不能为全部普通 C 函数盲目强加整函数汇编证明，也不能删除跨边界接口义务 |
| 汇编与外部效果 | native_link_contexts、native_contract_evidence | 对实际相关的汇编/运行库提供类型、寄存器、内存、终止等合同；没有 C AST 的对象不能自动免除 |
| 合法对象域 | validation_case、native_program_comparison | 显式对象初始化、容量/有效范围、生命周期、别名与函数前置条件；传入一个地址或观察一次成功不能证明合法性 |
| 候选实例覆盖 | native_entry_probe、native_program_scope | 进一步用实际编译后的实例位置、控制流和可复现输入建立覆盖；入口命中仅提供第一层证据。未命中要保留，不删掉目标来取得通过 |
| 原 L0–L3 与程序级审计 | translation_validation、validation_case、native_context_bridge | 通过经过核验的 TranslationArtifact/ProgramArtifact/ValidationPlan 和环境/比较合同进入原执行器；按适用性运行各层，未运行/不适用/未知分别保留，不伪造所需元数据 |

## A. 先验证旧实验上的新增入口观察

这一路复用旧构建的可核验证据，**不会补回旧响应文件字节**。旧归档缺口继续出现
是预期结果；若父审计源码清单变化，必须按下列步骤重新审计/部署，不能直接把
phase179 的部署结果交给新验证器绕过身份核验。每一步返回0且结果 check 通过后
再执行下一步；失败只提供首个失败日志，不检查不存在的 result.json。

### 1. 固定变量和新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE179_ROOT:?}"
git -C "$REPO" fetch origin phase180-response-entry-validation
export PHASE180_TOOLING="$PREP_ROOT/tooling-phase180"
git -C "$REPO" worktree add --detach "$PHASE180_TOOLING" origin/phase180-response-entry-validation
export PHASE180_ROOT="$(mktemp -d "$PHASE179_ROOT/phase180-XXXXXX")"
: "${PHASE180_ROOT:?}"
export PHASE180_PLAN="$PHASE179_ROOT/deployment/plan.json"
export PHASE180_CLANG="$(command -v clang-10)"
: "${PHASE180_CLANG:?}"
export PYTHONPATH="$PHASE180_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE180_CLI="$PHASE180_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE180_TOOLING" rev-parse HEAD
printf 'PHASE180_ROOT=%s\n' "$PHASE180_ROOT"
```

### 2. 回归

```bash
python3 -m pytest -q -rs \
  "$PHASE180_TOOLING/pytools/tests/test_gnu_response_files.py" \
  "$PHASE180_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE180_TOOLING/pytools/tests/test_project_build_capture.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_entry_probe.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_capture_scope.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_link_contexts.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_context_resolution.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_priority_contexts.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE180_TOOLING/pytools/tests/test_native_validation_cli.py" \
  --basetemp="$PHASE180_ROOT/pytest" > "$PHASE180_ROOT/focused.log" 2>&1
PHASE180_TEST_STATUS=$?
printf 'test_status=%s\n' "$PHASE180_TEST_STATUS"
cat "$PHASE180_ROOT/focused.log"
```

### 3. 审计

```bash
python3 "$PHASE180_CLI" audit-candidate --plan "$PHASE180_PLAN" \
  --output "$PHASE180_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE180_ROOT/audit.log" 2>&1
PHASE180_STATUS=$?
printf 'audit_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/audit.log"
```

```bash
python3 "$PHASE180_CLI" check-audit --plan "$PHASE180_PLAN" \
  --input "$PHASE180_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署

```bash
python3 "$PHASE180_CLI" deploy --plan "$PHASE180_PLAN" \
  --audit "$PHASE180_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE180_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE180_ROOT/deployment.log" 2>&1
PHASE180_STATUS=$?
printf 'deploy_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/deployment.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/deployment/result.json"
```

### 5. 运行与诊断映射

```bash
python3 "$PHASE180_CLI" observe --input "$PHASE180_ROOT/deployment/result.json" \
  --diagnostic --output "$PHASE180_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE180_ROOT/observation.log" 2>&1
PHASE180_STATUS=$?
printf 'observe_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/observation.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/observation/result.json"
```

```bash
python3 "$PHASE180_CLI" capture-runtime --observation "$PHASE180_ROOT/observation/result.json" \
  --output "$PHASE180_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE180_ROOT/runtime.log" 2>&1
PHASE180_STATUS=$?
printf 'runtime_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/runtime.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/runtime-identity/result.json"
```

### 6. 复用原生目标采集，产生本轮上下文桥

```bash
export PHASE180_REUSE_TARGET="$(python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE179_ROOT'])/'context-bridge/inputs.json'
print(json.loads(p.read_text())['targetReceipt']['path'])
PY
)"
: "${PHASE180_REUSE_TARGET:?}"
python3 "$PHASE180_CLI" inspect-context --plan "$PHASE180_ROOT/deployment/plan.json" \
  --observation "$PHASE180_ROOT/observation/result.json" --clang "$PHASE180_CLANG" \
  --reuse-native-input "$PHASE180_REUSE_TARGET" \
  --output "$PHASE180_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE180_ROOT/context.log" 2>&1
PHASE180_STATUS=$?
printf 'context_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/context.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/context-bridge/result.json"
```

### 7. 复用入口回执，生成全阶段基础合同

```bash
python3 - <<'PY' > "$PHASE180_ROOT/contracts.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE180_ROOT'])
old=json.loads((Path(os.environ['PHASE179_ROOT'])/'contracts-with-runtime/inputs.json').read_text())
cmd=[sys.executable,os.environ['PHASE180_CLI'],'inspect-contracts',
 '--context',str(root/'context-bridge/result.json'),'--observation',str(root/'observation/result.json'),
 '--runtime',str(root/'runtime-identity/result.json'),'--clang',os.environ['PHASE180_CLANG'],
 '--output',str(root/'contracts-with-runtime'),'--timeout-seconds','600']
for row in old['entryReceipts']:cmd+=['--reuse-entry-receipt',row['path']]
raise SystemExit(subprocess.call(cmd))
PY
PHASE180_STATUS=$?
printf 'contracts_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/contracts.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/contracts-with-runtime/result.json"
```

重点检查新增captureScopes里的真实阶段、归档producerBound及archiveProducerStages。
如果capturedProducerClosureComplete仍false，读具体reason；不将阶段遗漏假设当既定事实。
即使变true，也不能宣称ABI或完整链接闭包已通过。

### 8. 按上下文身份迁移已有首批回执

跨阶段恢复可能改变列表索引；不能把旧索引直接套用到新合同。以下按完整contextIdentity
定位新索引，复用之前的回执。缺失或变化会停止，不静默接受不兼容输入。

```bash
python3 - <<'PY' > "$PHASE180_ROOT/seed-batch.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE180_ROOT'])
base=root/'contracts-with-runtime/result.json'
report=json.loads(base.read_text())
positions={c['contextIdentity']:i for i,c in enumerate(report['producerContextClosure']['compileContexts'])}
old_rows=[]
for name in ('seed-batch','priority-batch'):
 file=Path(os.environ['PHASE179_ROOT'])/name/'result.json'
 if file.is_file():old_rows+=json.loads(file.read_text())['rows']
old={r['contextIdentity']:r for r in old_rows}
cmd=[sys.executable,os.environ['PHASE180_CLI'],'acquire-context-batch','--contracts',str(base),
 '--clang',os.environ['PHASE180_CLANG'],'--output',str(root/'seed-batch'),'--timeout-seconds','600']
for row in old.values():
 if not row['nativeInputAcquired']:continue
 cid=row['contextIdentity']
 if cid not in positions:raise ValueError('OLD_CONTEXT_NOT_PRESENT_IN_NEW_PRODUCER_GRAPH:'+cid)
 cmd+=['--context-index',str(positions[cid]),'--reuse-receipt',row['receipt']['path']]
if '--context-index' not in cmd:raise ValueError('NO_VALIDATED_SEED_CONTEXT')
raise SystemExit(subprocess.call(cmd))
PY
PHASE180_STATUS=$?
printf 'seed_batch_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/seed-batch.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/seed-batch/result.json"
```

### 9. 解析现有上下文并产生新的采集优先级

```bash
python3 "$PHASE180_CLI" resolve-contexts \
  --contracts "$PHASE180_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE180_ROOT/seed-batch/result.json" \
  --output "$PHASE180_ROOT/seed-resolution" > "$PHASE180_ROOT/seed-resolution.log" 2>&1
PHASE180_STATUS=$?
printf 'seed_resolution_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/seed-resolution.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/seed-resolution/result.json"
```

### 10. 独立重建并核验观察到的归档贡献

```bash
python3 "$PHASE180_CLI" audit-archive-selection \
  --deployment "$PHASE180_ROOT/deployment/result.json" \
  --output "$PHASE180_ROOT/archive-audit" --timeout-seconds 600 \
  > "$PHASE180_ROOT/archive-audit.log" 2>&1
PHASE180_STATUS=$?
printf 'archive_audit_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/archive-audit.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/archive-audit/result.json"
```

independentObservedArchiveContributionsVerified只对应观察到且可唯一归属的成员贡献。
没有归档、没有受支持贡献或不能复现时不能通过空集得到true。完整抽取闭包仍独立。

### 11. 自动采集下一批相关C上下文

```bash
python3 "$PHASE180_CLI" acquire-priority-contexts \
  --resolution "$PHASE180_ROOT/seed-resolution/result.json" \
  --clang "$PHASE180_CLANG" --count 4 --timeout-seconds 600 \
  --output "$PHASE180_ROOT/priority-batch" > "$PHASE180_ROOT/priority-batch.log" 2>&1
PHASE180_STATUS=$?
printf 'priority_batch_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/priority-batch.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/priority-batch/result.json"
```

仅处理最新报告中的优先索引，不复用旧的102/156等数字。若明确报告
PRIORITY_CONTEXT_NO_C_CONTEXT_PENDING，则没有可调度的C上下文；这不是语义通过。
这种情况下下一步只传seed批次，继续处理其他义务。

### 12. 累积上下文，接回原合同工作链

若第11步成功：

```bash
python3 "$PHASE180_CLI" resolve-contexts \
  --contracts "$PHASE180_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE180_ROOT/seed-batch/result.json" \
  --context-batch "$PHASE180_ROOT/priority-batch/result.json" \
  --output "$PHASE180_ROOT/context-resolution" > "$PHASE180_ROOT/resolution.log" 2>&1
PHASE180_STATUS=$?
printf 'resolution_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/resolution.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/context-resolution/result.json"
```

```bash
python3 "$PHASE180_CLI" refine-contracts \
  --input "$PHASE180_ROOT/contracts-with-runtime/result.json" \
  --context-resolution "$PHASE180_ROOT/context-resolution/result.json" \
  --archive-audit "$PHASE180_ROOT/archive-audit/result.json" \
  --output "$PHASE180_ROOT/contracts-resolved" > "$PHASE180_ROOT/refinement.log" 2>&1
PHASE180_STATUS=$?
printf 'refine_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/refinement.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/contracts-resolved/result.json"
```

### 13. 自动导出最终合同摘要

```bash
python3 "$PHASE180_CLI" summarize-contracts \
  --input "$PHASE180_ROOT/contracts-resolved/result.json" \
  --output "$PHASE180_ROOT/phase180-summary.json"
```

摘要为便于分析的派生视图，不是独立接受证书。stages和validationProgress均取最终
合同，避免旧摘要只显示基础合同。优先提供 focused.log、contracts.log、archive-audit.log、
priority-batch.log、refinement.log、phase180-summary.json；失败只需先提供首个失败日志。

### 14. 获取候选函数入口的实际观察

```bash
python3 "$PHASE180_CLI" capture-entry \
  --contracts "$PHASE180_ROOT/contracts-resolved/result.json" \
  --output "$PHASE180_ROOT/function-entry" --timeout-seconds 600 \
  > "$PHASE180_ROOT/function-entry.log" 2>&1
PHASE180_STATUS=$?
printf 'entry_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/function-entry.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/function-entry/result.json"
```

若权限/内核能力不足，查看 function-entry/trace/capture.json 的 failureReason；不能
将跳过或失败当成覆盖成功。若某个函数未进入，命令可以成功完成采集，但
candidateFunctionEntriesObserved 为 false。若编译器没有提供 linkerName 或定义不能
唯一归属，定位阶段直接拒绝，不根据函数名文本猜测地址。

### 15. 将入口观察接回原合同

```bash
python3 "$PHASE180_CLI" refine-contracts \
  --input "$PHASE180_ROOT/contracts-resolved/result.json" \
  --entry-coverage "$PHASE180_ROOT/function-entry/result.json" \
  --output "$PHASE180_ROOT/contracts-with-entry" \
  > "$PHASE180_ROOT/entry-refinement.log" 2>&1
PHASE180_STATUS=$?
printf 'entry_refinement_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/entry-refinement.log"
```

```bash
python3 "$PHASE180_CLI" check --input "$PHASE180_ROOT/contracts-with-entry/result.json"
```

```bash
python3 "$PHASE180_CLI" summarize-contracts \
  --input "$PHASE180_ROOT/contracts-with-entry/result.json" \
  --output "$PHASE180_ROOT/phase180-entry-summary.json"
```

验收：新子目标 instrumented-candidate-function-entry 仅在全部选定函数观察到入口时
verified；candidateInstructionExecutionCoverageVerified、nativeAbiClosureVerified、
legalObjectDomainVerified、untracedRunCoverageVerified 仍为 false。合同五个整体阶段
必须保持自身证据决定的状态，不能因新增子目标而整体通过。

## B. 重新捕获响应文件证据：独立的新实验状态

旧 configure 操作未封存 @conftest.lst 时，更新解析器不能修复过去没有记录的
字节。必须从 configure 开始重新构建，而非只重跑 make 或给旧记录附加当前文件。
以下复用已有 GMP 采集驱动及原构建 profile，不增加任何 GMP 名称匹配规则。

### 16. 生成新的目标采集计划

```bash
: "${PHASE168_ROOT:?}" "${PREP_ROOT:?}" "${ARCHIVE_ROOT:?}" "${PHASE180_ROOT:?}"
python3 "$PHASE180_TOOLING/experiment/advance_native_validation.py" prepare-target \
  --tooling "$PHASE180_TOOLING" --prep "$PREP_ROOT" --archives "$ARCHIVE_ROOT" \
  --profile "$PHASE168_ROOT/target-profile.json" \
  --requirements "$PHASE168_ROOT/requirements/result.json" \
  --timeout-seconds 3600 --output "$PHASE180_ROOT/fresh-target-plan.json" \
  > "$PHASE180_ROOT/fresh-prepare.log" 2>&1
PHASE180_STATUS=$?
printf 'prepare_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/fresh-prepare.log"
```

### 17. 从 configure 开始运行和核验

```bash
python3 "$PHASE180_TOOLING/experiment/advance_native_validation.py" run \
  --plan "$PHASE180_ROOT/fresh-target-plan.json" --output "$PHASE180_ROOT/fresh-target-run" \
  > "$PHASE180_ROOT/fresh-acquisition.log" 2>&1
PHASE180_STATUS=$?
printf 'fresh_acquisition_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/fresh-acquisition.log"
```

```bash
python3 "$PHASE180_TOOLING/experiment/advance_native_validation.py" check-run \
  --input "$PHASE180_ROOT/fresh-target-run"
```

### 18. 确认新 capture 的响应文件能力与展开证据

以下读取新构建记录所绑定的 capture，不从任意目录搜索同名文件。先确认文件存在：

```bash
ls -lh -- \
  "$PHASE180_ROOT/fresh-target-run/target-build/gmp-target/records.json" \
  "$PHASE180_ROOT/fresh-target-run/target-build/gmp-target/test-records.json"
```

再核验完整捕获并导出响应文件摘要：

```bash
python3 - <<'PYRESP' > "$PHASE180_ROOT/fresh-response-summary.json"
import json,os
from pathlib import Path
from riscv2x86_py.project_build_capture import load,inventory
from riscv2x86_py.native_dependency_inventory import checked_records
from riscv2x86_py.gnu_response_files import POLICY
root=Path(os.environ['PHASE180_ROOT'])
records=checked_records(root/'fresh-target-run/target-build/gmp-target/records.json')
config=load(records['captureConfig'])
if config['archiveCapture']['responseParserPolicy']!=POLICY:
 raise ValueError('NEW_RESPONSE_CAPTURE_PROFILE_REQUIRED')
replayed=inventory(records['captureConfig'],stage=None)
if not replayed['importComplete'] or replayed['unresolved']:
 raise ValueError('FULL_CAPTURE_REPLAY_INCOMPLETE')
rows=[]
for action in replayed['actions']:
 before=(action.get('archiveOperationEvidence') or {}).get('before',{})
 expansion=before.get('responseExpansion')
 if not expansion:continue
 rows.append({'actionIdentity':action['actionIdentity'],'arguments':action['arguments'],
  'supported':before['supported'],'reason':before.get('reason'),
  'responseExpansionIdentity':expansion['responseExpansionIdentity'],
  'executionMode':expansion['executionMode'],'fileCount':len(expansion['files'])})
print(json.dumps({'captureConfig':records['captureConfig'],'responseOperations':rows,
 'responseOperationCount':len(rows),'responseUseObserved':bool(rows),
 'semanticApproval':False},indent=2))
PYRESP
PHASE180_STATUS=$?
printf 'response_summary_status=%s\n' "$PHASE180_STATUS"
cat "$PHASE180_ROOT/fresh-response-summary.json"
```

inventory 已从封存响应文件重新推导展开和成员转换；摘要不能替代核验。
responseUseObserved=false 表示此次未重现响应文件使用，不能宣称原问题已实验验证。

新记录及其 capture.json 是重新准备部署计划的输入；候选仍须通过完整来源、输入
替换、声明/上下文、链接及独立审计检查。**不能将新 records.json 写回旧部署计划，
也不能仅凭文件名/内容碰巧一致替换旧 actionIdentity**。准备新部署计划后要完整
重复审计、部署和合同推导；最终是否消除归档缺口，取决于实际捕获动作及成员转换
是否完整通过。配置探测若没有再次使用响应文件，也不能据此声称重现了原缺口。

## 需要返回的结果与判断顺序

先给 focused.log。A 路线提供 function-entry.log、function-entry/result.json、
entry-refinement.log、phase180-entry-summary.json；如果入口采集失败，先给其日志和
trace/capture.json。B 路线提供 fresh-prepare.log、fresh-acquisition.log、
fresh-target-run/run-status.json、target-build/gmp-target/records.json 和
同目录 test-records.json。这些全部位于本次打印的 PHASE180_ROOT 下。

本轮只能按证据分别确认：响应文件捕获/冻结/回放能力是否有效；旧缺失证据是否仍
被拒绝；受限函数入口观察是否有效；该证据是否接回原合同。整体程序语义和完整
L0–L3 的完成条件没有放宽，仍需要前表中的后续实现。

## 本地验证记录

- 捕获/映射/入口/CLI 等相关回归：148 passed，2 skipped。
- 合同回接、解析、优先级、部署、观察和入口的最终集成回归：107 passed，1 skipped。
- 响应文件、归档生产与构建捕获最终回归：63 passed。
- 跳过均因当前环境禁止 ptrace；真实单次入口采集尚须在实验容器复验。
- 各组存在重叠，不能相加为不同用例总数。fixture 中被模拟的编译器/源码协议边界
  不算真实 RISC-V→x86 翻译验证；本地尚未运行用户 GMP 完整实验。

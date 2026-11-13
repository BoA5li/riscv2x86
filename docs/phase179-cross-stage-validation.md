# Phase179：跨阶段生产链、独立归档贡献审计与按需验证推进

基于 phase178-context-resolution，针对真实运行已经确认的归档选择候选0、当前范围
缺少操作证据、23个C上下文和7个汇编接口优先义务实施。所有选择由捕获身份、
完整路径/摘要、动作时间及实际符号关系驱动，不匹配GMP函数或文件名。

## 修订方案与完成范围

| 模块 | 实际修订 | 保留的边界 |
| --- | --- | --- |
| native_capture_scope | 从部署计划绑定的capture重新回放所有阶段；保留原选中动作身份；用配置/捕获/调用身份核对不同stage视图；记录真实父运行阶段 | 不信任旧unselectedActions；失败或无父运行的生产动作不能建立来源；不声称捕获全部进程 |
| native_link_contexts | 使用全阶段回放；恢复早期归档及其成员的编译来源；记录生产stage并检查原始捕获集合在推导期间未变 | 唯一性、时钟域、先生产后消费、归档摘要和成员顺序要求不变；仅按受限GNU工具语法排除只读查询或有明确不同目的归档的操作，目标归档上的不支持操作仍阻塞 |
| native_archive_selection | 复用已有GNU bfd映射语法及ELF解析；将唯一成员的普通已分配节、强符号、最终地址和大小关联 | 重名成员、TLS/merge/group或不支持布局不批准；缺少贡献行不能证明未抽取 |
| native_archive_audit | 复用原部署独立重建；比较完整ELF字节和重新推导的归档贡献关系 | 仅证明观察到的贡献，不证明全部抽取闭包、运行绑定、ABI或程序语义 |
| native_context_resolution | 对候选提供者边保守扩展跨编译单元潜在范围；保留所有歧义分支；同一物理定义保留出现位置而不产生虚假多提供者；候选替换严格限定到原库链接消费动作 | 潜在范围仅指导采集，不等于实际可达或执行；未访问不等于不可达 |
| native_context_batch / CLI | 支持非连续索引；acquire-priority-contexts自动从已核验解析结果中选择下一批 | 最多64项；无后续C上下文不代表完整验证通过；不硬编码旧索引 |
| native_validation_progress / 合同refine | 分开记录已验证子目标和未完成能力；独立归档审计接回原合同入口；摘要取最终合同 | 不把False改成True；不通过空列表或命令成功批准整个阶段 |

## 尚未完成的整体目标

本轮不是完整C程序证明器。实际源/候选/原生目标上下文兼容、x86和RV64机器ABI、
相关汇编效果、合法对象/输入域、自然运行和适用重定位效果、实际候选实例覆盖、
原L0–L3准入和独立程序级审计仍需要相应实现及真实证据。本轮不会声称全部缺口
已补齐。原ABI sidecar仅支持RV64标量，不能为使通过伪造x86完整事实。

归档具体历史状态仍应由新报告决定：若早期动作已在同一capture中，自动恢复；
若确实未捕获、阶段失败、发生变更或存在歧义，继续明确阻塞，不猜测生产链。

## 分步验证

每个命令成功后再执行下一条。失败先提供首个失败日志，不检查不存在的结果。
输出目录必须尚不存在。验证器源码清单变化，必须重新审计；原生CPP/AST事实
可经同工具、依赖、内容及完整上下文重新验证后复用。旧合同或旧审计结论不复用。

### 1. 固定变量和新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE178_ROOT:?}"
git -C "$REPO" fetch origin phase179-cross-stage-validation
export PHASE179_TOOLING="$PREP_ROOT/tooling-phase179"
git -C "$REPO" worktree add --detach "$PHASE179_TOOLING" origin/phase179-cross-stage-validation
export PHASE179_ROOT="$(mktemp -d "$PHASE178_ROOT/phase179-XXXXXX")"
: "${PHASE179_ROOT:?}"
export PHASE179_PLAN="$PHASE178_ROOT/deployment/plan.json"
export PHASE179_CLANG="$(command -v clang-10)"
: "${PHASE179_CLANG:?}"
export PYTHONPATH="$PHASE179_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE179_CLI="$PHASE179_TOOLING/experiment/advance_native_closure.py"
git -C "$PHASE179_TOOLING" rev-parse HEAD
printf 'PHASE179_ROOT=%s\n' "$PHASE179_ROOT"
```

### 2. 回归

```bash
python3 -m pytest -q -rs \
  "$PHASE179_TOOLING/pytools/tests/test_native_capture_scope.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_priority_contexts.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_context_resolution.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_link_contexts.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_program_scope.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE179_TOOLING/pytools/tests/test_project_archive_provenance.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE179_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  --basetemp="$PHASE179_ROOT/pytest" > "$PHASE179_ROOT/focused.log" 2>&1
PHASE179_TEST_STATUS=$?
printf 'test_status=%s\n' "$PHASE179_TEST_STATUS"
cat "$PHASE179_ROOT/focused.log"
```

### 3. 审计

```bash
python3 "$PHASE179_CLI" audit-candidate --plan "$PHASE179_PLAN" \
  --output "$PHASE179_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE179_ROOT/audit.log" 2>&1
PHASE179_STATUS=$?
printf 'audit_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/audit.log"
```

```bash
python3 "$PHASE179_CLI" check-audit --plan "$PHASE179_PLAN" \
  --input "$PHASE179_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署

```bash
python3 "$PHASE179_CLI" deploy --plan "$PHASE179_PLAN" \
  --audit "$PHASE179_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE179_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE179_ROOT/deployment.log" 2>&1
PHASE179_STATUS=$?
printf 'deploy_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/deployment.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/deployment/result.json"
```

### 5. 运行与诊断映射

```bash
python3 "$PHASE179_CLI" observe --input "$PHASE179_ROOT/deployment/result.json" \
  --diagnostic --output "$PHASE179_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE179_ROOT/observation.log" 2>&1
PHASE179_STATUS=$?
printf 'observe_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/observation.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/observation/result.json"
```

```bash
python3 "$PHASE179_CLI" capture-runtime --observation "$PHASE179_ROOT/observation/result.json" \
  --output "$PHASE179_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE179_ROOT/runtime.log" 2>&1
PHASE179_STATUS=$?
printf 'runtime_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/runtime.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/runtime-identity/result.json"
```

### 6. 复用原生目标采集，产生本轮上下文桥

```bash
export PHASE179_REUSE_TARGET="$(python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE178_ROOT'])/'context-bridge/inputs.json'
print(json.loads(p.read_text())['targetReceipt']['path'])
PY
)"
: "${PHASE179_REUSE_TARGET:?}"
python3 "$PHASE179_CLI" inspect-context --plan "$PHASE179_ROOT/deployment/plan.json" \
  --observation "$PHASE179_ROOT/observation/result.json" --clang "$PHASE179_CLANG" \
  --reuse-native-input "$PHASE179_REUSE_TARGET" \
  --output "$PHASE179_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE179_ROOT/context.log" 2>&1
PHASE179_STATUS=$?
printf 'context_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/context.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/context-bridge/result.json"
```

### 7. 复用入口回执，生成全阶段基础合同

```bash
python3 - <<'PY' > "$PHASE179_ROOT/contracts.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE179_ROOT'])
old=json.loads((Path(os.environ['PHASE178_ROOT'])/'contracts-with-runtime/inputs.json').read_text())
cmd=[sys.executable,os.environ['PHASE179_CLI'],'inspect-contracts',
 '--context',str(root/'context-bridge/result.json'),'--observation',str(root/'observation/result.json'),
 '--runtime',str(root/'runtime-identity/result.json'),'--clang',os.environ['PHASE179_CLANG'],
 '--output',str(root/'contracts-with-runtime'),'--timeout-seconds','600']
for row in old['entryReceipts']:cmd+=['--reuse-entry-receipt',row['path']]
raise SystemExit(subprocess.call(cmd))
PY
PHASE179_STATUS=$?
printf 'contracts_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/contracts.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/contracts-with-runtime/result.json"
```

重点检查新增captureScopes里的真实阶段、归档producerBound及archiveProducerStages。
如果capturedProducerClosureComplete仍false，读具体reason；不将阶段遗漏假设当既定事实。
即使变true，也不能宣称ABI或完整链接闭包已通过。

### 8. 按上下文身份迁移已有首批回执

跨阶段恢复可能改变列表索引；不能把旧索引直接套用到新合同。以下按完整contextIdentity
定位新索引，复用之前的回执。缺失或变化会停止，不静默接受不兼容输入。

```bash
python3 - <<'PY' > "$PHASE179_ROOT/seed-batch.log" 2>&1
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['PHASE179_ROOT'])
base=root/'contracts-with-runtime/result.json'
report=json.loads(base.read_text())
positions={c['contextIdentity']:i for i,c in enumerate(report['producerContextClosure']['compileContexts'])}
old=json.loads((Path(os.environ['PHASE178_ROOT'])/'context-batch/result.json').read_text())
cmd=[sys.executable,os.environ['PHASE179_CLI'],'acquire-context-batch','--contracts',str(base),
 '--clang',os.environ['PHASE179_CLANG'],'--output',str(root/'seed-batch'),'--timeout-seconds','600']
for row in old['rows']:
 if not row['nativeInputAcquired']:continue
 cid=row['contextIdentity']
 if cid not in positions:raise ValueError('OLD_CONTEXT_NOT_PRESENT_IN_NEW_PRODUCER_GRAPH:'+cid)
 cmd+=['--context-index',str(positions[cid]),'--reuse-receipt',row['receipt']['path']]
if '--context-index' not in cmd:raise ValueError('NO_VALIDATED_SEED_CONTEXT')
raise SystemExit(subprocess.call(cmd))
PY
PHASE179_STATUS=$?
printf 'seed_batch_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/seed-batch.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/seed-batch/result.json"
```

### 9. 解析现有上下文并产生新的采集优先级

```bash
python3 "$PHASE179_CLI" resolve-contexts \
  --contracts "$PHASE179_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE179_ROOT/seed-batch/result.json" \
  --output "$PHASE179_ROOT/seed-resolution" > "$PHASE179_ROOT/seed-resolution.log" 2>&1
PHASE179_STATUS=$?
printf 'seed_resolution_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/seed-resolution.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/seed-resolution/result.json"
```

### 10. 独立重建并核验观察到的归档贡献

```bash
python3 "$PHASE179_CLI" audit-archive-selection \
  --deployment "$PHASE179_ROOT/deployment/result.json" \
  --output "$PHASE179_ROOT/archive-audit" --timeout-seconds 600 \
  > "$PHASE179_ROOT/archive-audit.log" 2>&1
PHASE179_STATUS=$?
printf 'archive_audit_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/archive-audit.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/archive-audit/result.json"
```

independentObservedArchiveContributionsVerified只对应观察到且可唯一归属的成员贡献。
没有归档、没有受支持贡献或不能复现时不能通过空集得到true。完整抽取闭包仍独立。

### 11. 自动采集下一批相关C上下文

```bash
python3 "$PHASE179_CLI" acquire-priority-contexts \
  --resolution "$PHASE179_ROOT/seed-resolution/result.json" \
  --clang "$PHASE179_CLANG" --count 4 --timeout-seconds 600 \
  --output "$PHASE179_ROOT/priority-batch" > "$PHASE179_ROOT/priority-batch.log" 2>&1
PHASE179_STATUS=$?
printf 'priority_batch_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/priority-batch.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/priority-batch/result.json"
```

仅处理最新报告中的优先索引，不复用旧的102/156等数字。若明确报告
PRIORITY_CONTEXT_NO_C_CONTEXT_PENDING，则没有可调度的C上下文；这不是语义通过。
这种情况下下一步只传seed批次，继续处理其他义务。

### 12. 累积上下文，接回原合同工作链

若第11步成功：

```bash
python3 "$PHASE179_CLI" resolve-contexts \
  --contracts "$PHASE179_ROOT/contracts-with-runtime/result.json" \
  --context-batch "$PHASE179_ROOT/seed-batch/result.json" \
  --context-batch "$PHASE179_ROOT/priority-batch/result.json" \
  --output "$PHASE179_ROOT/context-resolution" > "$PHASE179_ROOT/resolution.log" 2>&1
PHASE179_STATUS=$?
printf 'resolution_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/resolution.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/context-resolution/result.json"
```

```bash
python3 "$PHASE179_CLI" refine-contracts \
  --input "$PHASE179_ROOT/contracts-with-runtime/result.json" \
  --context-resolution "$PHASE179_ROOT/context-resolution/result.json" \
  --archive-audit "$PHASE179_ROOT/archive-audit/result.json" \
  --output "$PHASE179_ROOT/contracts-resolved" > "$PHASE179_ROOT/refinement.log" 2>&1
PHASE179_STATUS=$?
printf 'refine_status=%s\n' "$PHASE179_STATUS"
cat "$PHASE179_ROOT/refinement.log"
```

```bash
python3 "$PHASE179_CLI" check --input "$PHASE179_ROOT/contracts-resolved/result.json"
```

### 13. 自动导出最终合同摘要

```bash
python3 "$PHASE179_CLI" summarize-contracts \
  --input "$PHASE179_ROOT/contracts-resolved/result.json" \
  --output "$PHASE179_ROOT/phase179-summary.json"
```

摘要为便于分析的派生视图，不是独立接受证书。stages和validationProgress均取最终
合同，避免旧摘要只显示基础合同。优先提供 focused.log、contracts.log、archive-audit.log、
priority-batch.log、refinement.log、phase179-summary.json；失败只需先提供首个失败日志。

## 完成判据

- 生产链缺口应由完整阶段证据闭合或给出具体缺失/失败原因，不能强制清空。
- 归档观察贡献须有独立重建、完整产物字节复现及对应关系一致；重复成员不能误配。
- 新C上下文只按最新身份/优先级采集；潜在跨模块范围可以扩大，不批准实际执行。
- 原合同必须重新核验并消费新结果；可验证的子目标为verified，五个整体阶段仍按
  各自全部必要条件判断。当前未实现完整机器ABI/对象域/执行覆盖及L0–L3准入。
- 新测试应覆盖真实跨阶段GCC/ar与链接、失败父阶段、伪造未选动作、原始捕获变更、
  稀疏索引及边界、歧义提供者、多次出现的物理定义、重复归档成员、独立审计篡改
  和合同回接。模拟Clang/source边界不算真实跨ISA验证。

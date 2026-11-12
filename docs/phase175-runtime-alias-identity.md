# Phase175：停止时路径关联、映射连续性与自动缺口盘点

## 问题、修订范围与验收边界

基于 phase174 `64dea7dae0df86ba6b3ad93f0f09472082505dfe`。
真实 GMP 运行报告有 301 条绑定事件、602 次端点出现，其中 96 次端点已关联，
506 次未关联。未关联项全部集中在动态库别名与后备文件规范路径之间。
这是一条实际失败线索，不是新实现的预期数量或通过阈值。

原实现主要按日志原始路径和映射路径的字面值连接；事后解析日志时还可能访问
已经变化的宿主机文件系统。它没有保存事件发生时的别名文件身份，无法严格地
用事后 `realpath` 补救。另一个缺口是完整映射行参与身份比较，将权限快照变化
与文件映射身份变化混在一起，同时不容易解释每条未验证记录的原因。

本轮完成上述关联及报告能力的修订，并让合同报告自动生成下一阶段证据需求。
**本轮不宣告五项程序级验证目标全部闭合**：自然运行关系、加载器 link_map
身份、重定位后内存效果、ABI、合法对象域、候选指令覆盖及 L0–L3 准入仍需独立证据。

## 具体方案和实现

| 问题或缺口 | 实现位置 | 方法与约束 |
| --- | --- | --- |
| 事后文件系统访问影响日志解释 | `native_binding_syntax.py`、`native_runtime_identity.py` | 新运行报告使用纯语法解析，保留原始标签，不再在报告派生时解析标签对应的当前文件 |
| 动态库路径别名不能关联 | `native_process_identity.py` | stderr write/writev 完成、子进程仍停止时，通过 `/proc/PID/root` 打开绝对路径，核查 regular file、前后 stat 和当前路径 stat，记录设备/inode/大小/时间戳及已捕获映像摘要 |
| 别名可能指向其他文件 | `native_runtime_identity.py` | 将同一 write 的别名 stat/摘要与其有效映射 epoch 的后备文件证据连接；缺失、失败、重复或不唯一均不批准 |
| 相同字节不能区分加载代次 | 两个运行模块 | 保存成功映射 syscall 的参数及返回值；依据设备/inode/文件快照、唯一 offset-zero 锚点和逐 epoch 连续性建立观察到的映射群身份。消失、迁移、覆盖重映射会切断连续性 |
| mprotect 造成无意义身份变化 | `native_runtime_identity.py` | 映射快照身份继续保存全部映射行；观察到的映射群身份不因权限变化单独改变。二者分别输出 |
| 同文件多次加载被按 inode 合并 | `native_runtime_identity.py` | 同一后备文件多个 offset-zero 锚点保持歧义，禁止按相同文件或 SONAME 合并。检查映射群包含该 inode/device 的全部映射，防止选择性遗漏 |
| 未验证原因不明确 | 运行报告 v2、CLI | 每个端点保留 write/epoch、候选数量、快照身份、映射群身份、别名证据和原因；符号元数据原因另行统计 |
| 零计数混淆“无证据”和“证据未闭合” | `native_contract_readiness.py`、合同报告 v2 | 自动生成各上下文的未解析调用、变参调用、缺失原生 ABI、对象/布局合同、入口输入缺口和重定位义务清单；运行证据状态明确区分 not-acquired、partial 和 diagnostic-endpoints-mapped |

这些规则不使用 GMP 符号名、库名、测试名或特定数量。ELF 符号及版本本身仍须
按实际元数据检查，COPY 目标存储不等于初始化提供者，IFUNC/TLS 义务不因身份
关联成功而消失。未知绑定模式不取得元数据兼容结论。

### 仍需遵守的范围

- 运行采集仍为单进程/单线程 Linux x86-64 ptrace 后端；事件命名空间仅支持 0。
- mmap/mprotect/munmap/mremap 保存成功的变更记录；shmat、shmdt、remap_file_pages
  和 pkey_mprotect 暂未建模，采集器明确拒绝，不能静默复用陈旧映射状态。
- `mappingInstanceIdentity` 是当前后端观察到的后备文件映射群连续性身份，
  **不是对加载器 link_map 实例的完整证明**；`loaderLoadInstanceIdentityVerified`
  保持 false。多锚点、没有锚点、重映射、跨 write 身份不一致继续未验证。
- 停止的是被跟踪子进程；不能由此证明其他进程无法修改文件或主机可信。
  stat/摘要证据不等于全部运行内存页与磁盘字节一致。
- 新采集只为同一次 write 内完整日志行保存路径别名。行跨 write 且某个 write
  缺少该别名证据时，报告 `STOPPED_ALIAS_EVIDENCE_MISSING`，不能借用事后 stat。
  这类结果要求进一步采集器支持，不能关闭检查。
- 对诊断标签的解释不证明日志不可伪造、实际函数调用或实际实现地址。
- `diagnosticEndpointMappingComplete=true` 仅表示本次已解析诊断事件的端点均有
  所要求的映射证据，且没有解析/映射采集失败；空事件集不会取得该结论。
- `requiredMappedImagesVerified` 仍仅表示所需映像摘要在捕获清单中出现，不能
  替代端点覆盖、加载代次或自然运行身份检查。
- 多种原因可能同时出现在一个端点；原因计数之和不一定等于未验证端点数。
- 合同 `coverageInventory` 是静态上下文盘点，不是已证明的可达调用集合，不能
  把不可达函数也当作运行覆盖要求，或把静态盘点为空当作通过。

## 五项实验目标的后续证据要求

| 目标 | 本轮可以推进的内容 | 仍须补足 |
| --- | --- | --- |
| 运行绑定 | 自动别名关联、映射连续性、逐条失败原因、版本和类型元数据检查 | 自然运行关联、真实加载器实例、适用重定位效果、COPY 初始化、IFUNC/TLS 等特殊合同 |
| 入口与 ABI | 复用原声明和入口上下文，自动列出缺少定义、间接/变参调用、原生 machine join 需求 | 原生参数/返回值/调用约定/布局事实与声明及双端编译上下文的完整对应 |
| 合法对象与输入 | 按对象证据身份定位初始化、生命周期、边界和别名合同缺口 | 实际合法输入域、对象状态和函数前置条件的证明；静态初始化 AST 不替代证明 |
| 输出与终止 | 继续复用现有有限进程比较器；有比较证据时关联其真实状态 | 外部效果、错误/保护失败路径及执行机制之间的终止关系 |
| 程序级验证 | 明确静态盘点与实际执行覆盖不同；保留原框架准入缺口 | 候选实例执行证据、适用 L0–L3 接入与程序级独立审计 |

此方案通过补充证据接入原框架，不另外建立可绕过原框架的语义批准路线。

## 证据版本和迁移

运行捕获和运行报告升级为 v2；旧 v1 记录没有停止时别名或映射变更参数，不能
事后补写成 v2。检查旧运行报告将给出明确 recapture 要求。
合同报告也升级为 v2，要求重新派生缺口盘点。

验证器源码清单已变化，**必须按下列步骤重新审计、部署和采集**。不能直接用新
工具消费 phase174 审计链，也不能修改旧回执的 verifierIdentity、schemaVersion
或通过标志。保留 phase174 目录作为历史证据。

## 分步实验验证

每步退出码为 0 后再进行下一步；失败时先提供首个失败日志，不检查尚未生成的
result.json。全部输出放在新目录；不要预先 mkdir 工具要创建的输出目录。

### 1. 设置所有变量并获取新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE174_ROOT:?}"
git -C "$REPO" fetch origin phase175-runtime-alias-identity
export PHASE175_TOOLING="$PREP_ROOT/tooling-phase175"
git -C "$REPO" worktree add --detach "$PHASE175_TOOLING" origin/phase175-runtime-alias-identity
export PHASE175_ROOT="$(mktemp -d "$PHASE174_ROOT/phase175-XXXXXX")"
: "${PHASE175_ROOT:?}"
export PHASE175_PLAN="$PHASE174_ROOT/deployment/plan.json"
export PHASE175_CLANG="$(command -v clang-10)"
: "${PHASE175_CLANG:?clang-10 unavailable}"
export PYTHONPATH="$PHASE175_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE175_TOOLING" rev-parse HEAD
printf 'PHASE175_ROOT=%s\n' "$PHASE175_ROOT"
ls -lh -- "$PHASE175_PLAN"
```

### 2. 执行相关回归

```bash
python3 -m pytest -q -rs \
  "$PHASE175_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_program_comparison.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE175_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_validation_cli.py" \
  "$PHASE175_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  --basetemp="$PHASE175_ROOT/pytest" > "$PHASE175_ROOT/focused.log" 2>&1
PHASE175_TEST_STATUS=$?
printf 'phase175_test_status=%s\n' "$PHASE175_TEST_STATUS"
cat "$PHASE175_ROOT/focused.log"
```

ptrace 或真实工具链不可用时，测试会明确 skip，不计作真实采集成功。

### 3. 重新审计候选

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "${PHASE175_PLAN:?}" --output "$PHASE175_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE175_ROOT/candidate-audit.log" 2>&1
PHASE175_AUDIT_STATUS=$?
printf 'phase175_audit_status=%s\n' "$PHASE175_AUDIT_STATUS"
cat "$PHASE175_ROOT/candidate-audit.log"
```

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "${PHASE175_PLAN:?}" --input "$PHASE175_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署并检查

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "${PHASE175_PLAN:?}" --audit "$PHASE175_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE175_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE175_ROOT/deployment.log" 2>&1
PHASE175_DEPLOY_STATUS=$?
printf 'phase175_deploy_status=%s\n' "$PHASE175_DEPLOY_STATUS"
cat "$PHASE175_ROOT/deployment.log"
```

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE175_ROOT/deployment/result.json"
```

### 5. 获取新的目标观察

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE175_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE175_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE175_ROOT/observation.log" 2>&1
PHASE175_OBSERVATION_STATUS=$?
printf 'phase175_observation_status=%s\n' "$PHASE175_OBSERVATION_STATUS"
cat "$PHASE175_ROOT/observation.log"
```

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE175_ROOT/observation/result.json"
```

### 6. 采集 v2 运行证据

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" capture-runtime \
  --observation "$PHASE175_ROOT/observation/result.json" \
  --output "$PHASE175_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE175_ROOT/runtime-identity.log" 2>&1
PHASE175_RUNTIME_STATUS=$?
printf 'phase175_runtime_status=%s\n' "$PHASE175_RUNTIME_STATUS"
cat "$PHASE175_ROOT/runtime-identity.log"
```

成功后检查：

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE175_ROOT/runtime-identity/result.json"
```

失败时保留 `runtime-identity/trace/capture.json`，其中记录采集失败原因。

### 7. 按实际记录检查身份关联结果

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['PHASE175_ROOT'])
r=json.loads((root/'runtime-identity/result.json').read_text())
keys=['schemaVersion','bindingEventCount','endpointOccurrenceCount',
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
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE175_ROOT/deployment/plan.json" \
  --observation "$PHASE175_ROOT/observation/result.json" --clang "$PHASE175_CLANG" \
  --output "$PHASE175_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE175_ROOT/context-bridge.log" 2>&1
PHASE175_CONTEXT_STATUS=$?
printf 'phase175_context_status=%s\n' "$PHASE175_CONTEXT_STATUS"
cat "$PHASE175_ROOT/context-bridge.log"
```

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" inspect-contracts \
  --context "$PHASE175_ROOT/context-bridge/result.json" \
  --observation "$PHASE175_ROOT/observation/result.json" --clang "$PHASE175_CLANG" \
  --runtime "$PHASE175_ROOT/runtime-identity/result.json" \
  --output "$PHASE175_ROOT/contracts-with-runtime" --timeout-seconds 600 \
  > "$PHASE175_ROOT/contracts-with-runtime.log" 2>&1
PHASE175_CONTRACT_STATUS=$?
printf 'phase175_contract_status=%s\n' "$PHASE175_CONTRACT_STATUS"
cat "$PHASE175_ROOT/contracts-with-runtime.log"
```

```bash
python3 "$PHASE175_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE175_ROOT/contracts-with-runtime/result.json"
```

如果运行采集失败，仍可省略 `--runtime` 采集静态合同；这时状态应为
`not-acquired`，不能把零计数当作“无缺口”。

### 9. 获取自动盘点以安排后续证明

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE175_ROOT'])/'contracts-with-runtime/result.json'
r=json.loads(p.read_text())
print(json.dumps({'stages':r['stages'],'coverageInventory':r['coverageInventory']},
                 indent=2,ensure_ascii=False))
PY
```

请提供步骤 7 的摘要与本步骤的结果。没有任何阶段能仅凭 `evidenceOperationComplete`
或退出码 0 宣告语义完成。

### 10. 有限源目标进程比较

复用 [phase174 步骤 8](phase174-runtime-contract-evidence.md#8-明确源端运行配置后进行有限程序观察比较)
的既有比较功能，但所有工具、部署、计划及输出路径使用本次 `PHASE175_TOOLING`
和 `PHASE175_ROOT`；不要引用旧部署比较计划。
必须先从原源端基线记录确定实际 RISC-V 可执行文件、运行器、sysroot、参数、环境
与工作目录，不能猜测或用目标程序充当源端。

成功比较后可用本轮 `refine-contracts --input
"$PHASE175_ROOT/contracts-with-runtime/result.json" --comparison <本轮比较结果>
--output <全新目录>` 关联。有限观察比较继续不批准内部对象域、源执行机制或 L1。

## 回归范围

测试覆盖实际 ELF/编译/链接边界，以及明确标注的合成 syscall 回执：停止时符号
链接身份、文件更换、别名证据缺失/重复、错误 inode/摘要、权限变化、卸载重载、
相同地址和字节的覆盖重映射、多加载锚点、选择性遗漏映射、陈旧 epoch、旧版本
拒绝、空事件集、未知绑定模式、声明/对象/变参缺口盘点及重新派生篡改检查。
合成回执不构成真实采集或跨 ISA 证明；真实 ptrace 测试在受限环境中可明确跳过。

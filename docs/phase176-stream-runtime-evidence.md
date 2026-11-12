# Phase176：跨写入日志与停止时身份采集

## 三个前置阶段的含义

假设测试调用一个接收两个大整数并返回运算结果的函数。

| 阶段 | 通俗理解 | 对整体实验的作用 |
| --- | --- | --- |
| 运行绑定 | 调用的到底是哪一个函数、哪一份库、哪个符号版本？例如是否实际用了翻译后部署的库 | 排除系统库替代、错误版本或错误提供者导致的假成功；绑定事件仍不等于函数指令实际执行 |
| 入口与 ABI | 调用双方怎样传递和解释参数、返回值与寄存器？例如都是64位整数，而不是一端按32位接收 | 排除调用接口造成的错误；C声明相同也不独立证明机器级ABI一致 |
| 合法对象与输入 | 传入的指针是否指向有效且已初始化的对象，数组是否足够大，别名与输入范围是否满足要求？ | 排除未定义行为，使结果比较具备解释力；仅观察正常退出不能证明合法输入域 |

三者与翻译器的局部语义证明共同为程序级验证建立前提，不是另一条独立翻译路线。
例如局部乘法转换正确，但测试实际调用系统库、参数传递错误或输出数组越界时，
不能把程序结果用于证明这次翻译正确。

## 已确认的实现错误

本轮基于 phase175 `b112a046019502f20354ba6d65f9762a7262c822`。
用户提供的 v2 采集回执记录629次写入，绑定日志包含301条事件；每条事件均跨
两次写入。126条为正文加版本尾部/换行，175条为正文加单独换行。
最终完整日志可以解析，但逐write解析完整行无法识别任何一次写入中的完整事件，
所以所有 bindingAliases 均为空，592次绝对路径端点未验证。

旧实现对缺少证据保持未验证是正确的，但并未满足实际加载器分片输出的采集需求。
此前测试只确认缺少换行时不采集，没有覆盖真实正文/尾部的成功采集与严格关联。

## 详细修订方案及实现

| 环节 | 实现位置 | 方法和验收要求 |
| --- | --- | --- |
| 增量字节流 | `native_binding_syntax.BindingStream` | 保存未完成记录、绝对行起点和端点头部字节终点；以LF划分记录而非以syscall划分；支持多记录、尾部、UTF-8字节切分及EOF无换行 |
| 端点可观察时机 | `BindingStream.feed` | 完整端点头部出现后即可采集路径；头部不证明符号或版本，最终完整记录另行解析 |
| 停止时文件证据 | `native_process_identity.binding_aliases`、`capture` | 每次写入完成且子进程停止时，针对该时刻可见的头部采集stat和已有映像摘要；后续版本/换行片段继续重新采集，不能复制前次stat |
| 证据接口 | process-map-capture v3 | 每次写入保存bindingHeaders和bindingAliases；保留offset/size/epoch/stopOrdinal；旧v2不能改版本后复用 |
| 独立重新派生 | `native_runtime_identity.derive` | 使用原日志和写入区间重放增量解析，精确比较头部观察；没有可见头部的别名证据被拒绝 |
| 端点关联 | `associate` | 按最终记录字节范围，将每个端点逐片关联到该记录自己的可见头部和当时别名；仍要求每次相关写入的文件/映射证据及连续性，保留PID、命名空间与歧义限制 |
| 最终符号合同 | 既有元数据检查 | 版本尾部到齐后再判断版本、类型和提供者；未知版本、COPY/IFUNC/TLS等义务不因解析成功而消失 |
| 资源边界 | 流解析及既有采集预算 | 单行最多1MiB；保留总日志、映像、元数据、停止次数和超时预算；无效UTF-8明确失败 |
| 验证诊断 | runtime report v3、CLI | 输出streamHeaderReplayVerified、fragmentedBindingEventCount及逐片endpointHeaderObservable；使用原有原因清单和合同盘点定位后续缺口 |

所有路径、符号、片段数量和长度均来自实际字节流；没有GMP名称白名单或历史计数阈值。

### 为什么不会放宽证明要求

1. 没有删除“每次相关写入均有证据”的要求。
2. 没有用完整日志的事后路径解析替代停止时stat。
3. 没有仅凭同一映射epoch认定路径身份不变。路径可在两次写入间被替换，
   因此即使epoch相同，也在第二个停止点重新采集。
4. 没有在正文阶段默认符号没有版本；正文只用于观察端点，符号检查等待最终记录。
5. 如果初期片段还未包含完整端点头部，明确记录
   `ENDPOINT_HEADER_NOT_YET_OBSERVABLE`，不能将后续stat回填到过去。
   这是可解释的证据不足，不是解析器停止工作。支持任意分片的语法解析不意味着
   每种分片都能在当前后端取得覆盖整个记录期间的路径历史证明。
6. 相同文件字节、多实例、卸载重载、覆盖重映射、命名空间及自然运行边界保持不变。

### 本次真实日志重放的结论边界

对上传文本恢复LF后，摘要与采集回执一致。按原629次写入区间重放新解析器，
301条事件的602个相关片段均可观察到完整端点头部。这验证了本次分片模式被覆盖。
**该重放不产生停止时文件stat，不把旧v2结果升级为v3，不证明602次端点身份已通过。**
实际身份和符号合同必须使用新工具在宿主机上重新采集验证。

## 其余阶段的完整方案与当前边界

本轮完成当前已定位的流解析、采集及关联错误；不能据此宣布所有实验目标完成。

| 后续工作 | 正确实施依据 | 当前状态与下一步 |
| --- | --- | --- |
| 自然运行与特殊重定位 | 实际加载器实例/解析目标、适用COPY初始化、IFUNC解析器和TLS状态等证据 | ptrace诊断结果不替代自然运行；v3继续保留未验证义务 |
| 入口与ABI | 真实调用点与声明ID、双端原生编译上下文、参数和返回值、变参、寄存器/栈及类型布局；送入现有machine join | 已有静态盘点和部分入口上下文；缺少原生事实时不批准，需读取完整contracts报告逐项定位 |
| 合法对象与输入 | 明确的有效输入域，以及对象初始化、存活期、大小/对齐、别名与前置条件证据 | 静态AST和有限进程输入描述不能代替证明；需结合真实测试入口的调用域补足，不按函数名假定合法 |
| 输出和终止 | 源端真实基线、运行器/sysroot、参数/环境/输入，以及错误、外部效果与终止比较合同 | 复用已有进程比较器；没有源端运行配置时不能猜测路径或以目标程序代替源端 |
| 程序级准入 | 候选实例实际执行覆盖、已有局部证明的适用条件、L0–L3及独立程序级审计 | 绑定事件不等于调用覆盖；保留原框架准入要求 |

五项目标仍输出真实完成度。`semanticApproval`、`productionAcceptanceComplete`、
`untracedRuntimeBindingClosureComplete` 不因本轮修复而提升。
现有完整runtime报告只足以定位运行阶段的本次错误，不能单独推导ABI和对象合同。

## 回归与证据迁移

新增回归包括正文/换行分开、正文/版本尾部、无换行EOF、逐字节切分与UTF-8切分、
一次写入多事件、记录边界隔离、单行预算、错误编码、真实文件别名采集、
同epoch路径替换、早期不可见头部不回填、重算摘要后的头部篡改拒绝。
保留既有映射变更、版本/类型、独立审计和合同回归。

捕获和运行报告升级v3；合同报告继续使用现有v2结构，并通过其runtime引用消费v3。
验证器源码清单变化，所以必须重新审计、部署、观察和采集。不能直接检查或改写
旧v2运行报告来代替重跑。保留phase175结果作为历史证据。

本开发环境相关回归：**203 passed，4 skipped**。跳过项分别涉及真实ptrace、真实
Clang、RISC-V GCC/Clang组合以及完整原生翻译前端。跳过不计作真实能力验证通过。
文档中的Bash/Python指令通过语法检查，`git diff --check`通过。

## 分步实验验证

每步退出码为 0 后再进行下一步；失败时先提供首个失败日志，不检查尚未生成的
result.json。全部输出放在新目录；不要预先 mkdir 工具要创建的输出目录。

### 1. 设置所有变量并获取新工具

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE175_ROOT:?}"
git -C "$REPO" fetch origin phase176-stream-runtime-evidence
export PHASE176_TOOLING="$PREP_ROOT/tooling-phase176"
git -C "$REPO" worktree add --detach "$PHASE176_TOOLING" origin/phase176-stream-runtime-evidence
export PHASE176_ROOT="$(mktemp -d "$PHASE175_ROOT/phase176-XXXXXX")"
: "${PHASE176_ROOT:?}"
export PHASE176_PLAN="$PHASE175_ROOT/deployment/plan.json"
export PHASE176_CLANG="$(command -v clang-10)"
: "${PHASE176_CLANG:?clang-10 unavailable}"
export PYTHONPATH="$PHASE176_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE176_TOOLING" rev-parse HEAD
printf 'PHASE176_ROOT=%s\n' "$PHASE176_ROOT"
ls -lh -- "$PHASE176_PLAN"
```

### 2. 执行相关回归

```bash
python3 -m pytest -q -rs \
  "$PHASE176_TOOLING/pytools/tests/test_native_binding_stream.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_program_comparison.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE176_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_validation_cli.py" \
  "$PHASE176_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  --basetemp="$PHASE176_ROOT/pytest" > "$PHASE176_ROOT/focused.log" 2>&1
PHASE176_TEST_STATUS=$?
printf 'phase176_test_status=%s\n' "$PHASE176_TEST_STATUS"
cat "$PHASE176_ROOT/focused.log"
```

ptrace 或真实工具链不可用时，测试会明确 skip，不计作真实采集成功。

### 3. 重新审计候选

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "${PHASE176_PLAN:?}" --output "$PHASE176_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE176_ROOT/candidate-audit.log" 2>&1
PHASE176_AUDIT_STATUS=$?
printf 'phase176_audit_status=%s\n' "$PHASE176_AUDIT_STATUS"
cat "$PHASE176_ROOT/candidate-audit.log"
```

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "${PHASE176_PLAN:?}" --input "$PHASE176_ROOT/candidate-audit/deployment-audit.json"
```

### 4. 部署并检查

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "${PHASE176_PLAN:?}" --audit "$PHASE176_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE176_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE176_ROOT/deployment.log" 2>&1
PHASE176_DEPLOY_STATUS=$?
printf 'phase176_deploy_status=%s\n' "$PHASE176_DEPLOY_STATUS"
cat "$PHASE176_ROOT/deployment.log"
```

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE176_ROOT/deployment/result.json"
```

### 5. 获取新的目标观察

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE176_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE176_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE176_ROOT/observation.log" 2>&1
PHASE176_OBSERVATION_STATUS=$?
printf 'phase176_observation_status=%s\n' "$PHASE176_OBSERVATION_STATUS"
cat "$PHASE176_ROOT/observation.log"
```

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE176_ROOT/observation/result.json"
```

### 6. 采集 v3 运行证据

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" capture-runtime \
  --observation "$PHASE176_ROOT/observation/result.json" \
  --output "$PHASE176_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE176_ROOT/runtime-identity.log" 2>&1
PHASE176_RUNTIME_STATUS=$?
printf 'phase176_runtime_status=%s\n' "$PHASE176_RUNTIME_STATUS"
cat "$PHASE176_ROOT/runtime-identity.log"
```

成功后检查：

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE176_ROOT/runtime-identity/result.json"
```

失败时保留 `runtime-identity/trace/capture.json`，其中记录采集失败原因。

### 7. 按实际记录检查身份关联结果

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['PHASE176_ROOT'])
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
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE176_ROOT/deployment/plan.json" \
  --observation "$PHASE176_ROOT/observation/result.json" --clang "$PHASE176_CLANG" \
  --output "$PHASE176_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE176_ROOT/context-bridge.log" 2>&1
PHASE176_CONTEXT_STATUS=$?
printf 'phase176_context_status=%s\n' "$PHASE176_CONTEXT_STATUS"
cat "$PHASE176_ROOT/context-bridge.log"
```

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" inspect-contracts \
  --context "$PHASE176_ROOT/context-bridge/result.json" \
  --observation "$PHASE176_ROOT/observation/result.json" --clang "$PHASE176_CLANG" \
  --runtime "$PHASE176_ROOT/runtime-identity/result.json" \
  --output "$PHASE176_ROOT/contracts-with-runtime" --timeout-seconds 600 \
  > "$PHASE176_ROOT/contracts-with-runtime.log" 2>&1
PHASE176_CONTRACT_STATUS=$?
printf 'phase176_contract_status=%s\n' "$PHASE176_CONTRACT_STATUS"
cat "$PHASE176_ROOT/contracts-with-runtime.log"
```

```bash
python3 "$PHASE176_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE176_ROOT/contracts-with-runtime/result.json"
```

如果运行采集失败，仍可省略 `--runtime` 采集静态合同；这时状态应为
`not-acquired`，不能把零计数当作“无缺口”。

### 9. 获取自动盘点以安排后续证明

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ['PHASE176_ROOT'])/'contracts-with-runtime/result.json'
r=json.loads(p.read_text())
print(json.dumps({'stages':r['stages'],'coverageInventory':r['coverageInventory']},
                 indent=2,ensure_ascii=False))
PY
```

请提供步骤 7 的摘要与本步骤的结果。没有任何阶段能仅凭 `evidenceOperationComplete`
或退出码 0 宣告语义完成。

### 10. 有限源目标进程比较

复用 [phase174 步骤 8](phase174-runtime-contract-evidence.md#8-明确源端运行配置后进行有限程序观察比较)
的既有比较功能，但所有工具、部署、计划及输出路径使用本次 `PHASE176_TOOLING`
和 `PHASE176_ROOT`；不要引用旧部署比较计划。
必须先从原源端基线记录确定实际 RISC-V 可执行文件、运行器、sysroot、参数、环境
与工作目录，不能猜测或用目标程序充当源端。

成功比较后可用本轮 `refine-contracts --input
"$PHASE176_ROOT/contracts-with-runtime/result.json" --comparison <本轮比较结果>
--output <全新目录>` 关联。有限观察比较继续不批准内部对象域、源执行机制或 L1。


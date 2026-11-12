# Phase174：运行映射、合同证据与有限程序观察比较

本轮基于 phase173，补充实际运行映射采集、结构化合同输入及有限程序比较。
**本轮没有完成全部五项目标的语义闭合。** 没有证据的 ABI、对象合法性、自然运行
绑定、实例指令覆盖和 L0–L3 验收仍为未解决，不能据此修改批准标志。

## 实现内容与边界

| 能力 | 已实现 | 不代表什么 |
| --- | --- | --- |
| 运行身份采集 | 单进程 Linux x86-64 ptrace 后端；在 exec 和映射变化后采集映射，以 stderr write/writev 的时序关联诊断事件；保存后备文件设备/inode/字节快照及虚拟 ELF 映像 | 不证明无干预自然运行、全部重定位后内存页、日志来源真实性或实际函数调用 |
| 符号和特殊角色 | 检查捕获映像中的符号、版本、类型、版本文件约束；区分 COPY 目标存储与普通定义；显式保留 IFUNC 等特殊义务 | 不证明 COPY 初始化字节、解析器最终实现地址或对象行为 |
| 声明与调用 | 沿已验证的字节编辑映射关联源/候选声明；按声明 ID 与 previousDecl 链关联调用和定义；保留类型图和初始化 AST | 类型字符串相同不等于原生 ABI 或对象合法性 |
| 测试入口上下文 | 从捕获的链接输入、对象摘要和生产时序自动定位直接对象生产者，复用原生输入采集 | 归档成员与外部提供者未展开的部分保留 entryInputGaps；不宣告完整入口闭包 |
| 程序观察比较 | 复用原有 compare_l1_observations 和 ComparisonContract，对明确调用配置的退出码、stdout、stderr 精确比较 | 不批准 L1 适用性、对象域、内部结果、源执行机制或翻译实例覆盖 |
| 合同证据复用 | refine-contracts 验证原报告后复用入口回执，关联新的运行/比较证据，不重复编译 | 不忽略旧证据变化或父部署不匹配 |
| 输入错误诊断 | 空路径、目录等 plan/context/observation 输入在采集前被拒绝 | 不改变任何翻译或评估通过条件 |

TLS 等重定位按 ELF machine/type 选择合同义务，不按项目符号名识别。识别类型
只生成所需事实，仍不批准运行语义。旧 v2/v3 观察报告的重定位推导规则没有被静默改写。

所有新报告都能通过 `check` 重新派生；修改字节、输入身份、命令配置或重新计算摘要
后篡改完成结论都会被拒绝。此机制检查与采集记录的一致性，不是对不可信主机的认证。

## 运行采集后端的支持范围

- Linux x86-64、普通非特权目标、单进程/单线程目标与单线程采集器。
- 要求系统允许父进程 ptrace 子进程，并提供 `PTRACE_GET_SYSCALL_INFO`。
  入口/退出阶段由内核提供，不能通过猜测交替顺序替代。缺少能力时明确失败。
- 拒绝 fork/clone、再次 exec、stderr 重绑定和未支持的 syscall ABI。
- 设置超时、日志、映像、映射数量/元数据及停止次数预算；保留失败记录。
- 后备文件快照核对设备/inode和读取期间的 stat，**不声称完整运行内存字节等于磁盘文件**。
- ptrace 和 LD_DEBUG 均有干预；新运行的工作目录也与原观察不同。输出/返回码相同
  只是所记录观察的一致性，不能证明干预无影响。
- 事件关联仅支持加载器命名空间 0。其他命名空间、别名无法唯一关联、映射捕获失败、
  符号/版本/类型不一致均保留未验证结果；不能为提升计数而放宽。

如果系统不允许采集，保留 `trace/capture.json` 和日志，运行身份目标继续未完成。
不要修改回执或把不可用计为覆盖成功。静态合同输入可以单独采集，但不能据此宣布运行阶段通过。

## 对五项目标的实际完成度

| 目标 | 本轮推进 | 仍需实现/证明 |
| --- | --- | --- |
| 运行绑定 | 可获得带时序的诊断映射与符号元数据关联 | 自然运行关系、真实解析目标、适用重定位效果及特殊情况的完整闭包 |
| 入口与 ABI | 自动入口直接对象上下文、三方声明/类型/调用证据 | 原生 ABI/机器事实、归档与外部调用闭包、源/目标上下文语义关系 |
| 合法对象与输入 | 对象声明、初始化表达式及类型图 | 有效输入域、初始化语义、生命周期、边界、别名和前置条件证明 |
| 输出与终止 | 可执行有限调用的双端字节比较 | 内部及外部效果、错误/保护失败路径和终止关系的完整合同 |
| 程序级验证 | 证据可复用并与现有比较器关联 | 实例指令覆盖、通用 L0–L3 适用性、程序级独立审计 |

完整 ABI 合同仍使用原有 machine join 的要求；不会将 Clang 声明转换成伪造的
原生 ABI 证明。进程比较的 `verified` 仅属于 `processObservableComparisonStatus`。
`l1EligibilityVerified`、`semanticApproval`、`productionAcceptanceComplete` 保持 false。
源基线不满足声明退出域、执行超时/日志超限时不能得到比较成功；有效基线与目标
观察不同则记录 failed。stdout/stderr 使用 Base64 无损传输后交给原比较器，不删除
空白、不替换路径、不忽略不可解码字节。

# 宿主机分步验证

每个步骤退出码为 0 后再继续；首个失败日志比后续缺失文件报错更有意义。
使用新目录，保留 phase173 的历史结果。源码包发生变化，按 phase173 的严格清单
规则，**本次必须重新审计并部署，不能直接消费旧审计链来跳过这些步骤**。

## 1. 更新工具并一次性明确设置变量

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE173_ROOT:?}"
git -C "$REPO" fetch origin phase174-runtime-contract-evidence
export PHASE174_TOOLING="$PREP_ROOT/tooling-phase174"
git -C "$REPO" worktree add --detach "$PHASE174_TOOLING" origin/phase174-runtime-contract-evidence
export PHASE174_ROOT="$(mktemp -d "$PHASE173_ROOT/phase174-XXXXXX")"
: "${PHASE174_ROOT:?}"
export PHASE174_PLAN="$PHASE173_ROOT/deployment/plan.json"
export PHASE174_CLANG="$(command -v clang-10)"
: "${PHASE174_CLANG:?clang-10 unavailable}"
export PYTHONPATH="$PHASE174_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE174_TOOLING" rev-parse HEAD
printf 'PHASE174_ROOT=%s\n' "$PHASE174_ROOT"
ls -lh -- "$PHASE174_PLAN"
```

## 2. 相关回归

```bash
python3 -m pytest -q -rs \
  "$PHASE174_TOOLING/pytools/tests/test_native_runtime_identity.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_program_comparison.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_contract_evidence.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE174_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_validation_cli.py" \
  "$PHASE174_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  --basetemp="$PHASE174_ROOT/pytest" > "$PHASE174_ROOT/focused.log" 2>&1
PHASE174_TEST_STATUS=$?
printf 'phase174_test_status=%s\n' "$PHASE174_TEST_STATUS"
cat "$PHASE174_ROOT/focused.log"
```

明确标注的模拟 Clang/证明边界夹具不构成真实跨 ISA 证明。ptrace 不可用时相应测试
会跳过并记录原因；需要另看目标宿主机上的能力与实际采集结果。

## 3. 重新审计、检查，再部署

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "${PHASE174_PLAN:?}" --output "$PHASE174_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE174_ROOT/candidate-audit.log" 2>&1
PHASE174_AUDIT_STATUS=$?
printf 'phase174_audit_status=%s\n' "$PHASE174_AUDIT_STATUS"
cat "$PHASE174_ROOT/candidate-audit.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "${PHASE174_PLAN:?}" --input "$PHASE174_ROOT/candidate-audit/deployment-audit.json"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "${PHASE174_PLAN:?}" --audit "$PHASE174_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE174_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE174_ROOT/deployment.log" 2>&1
PHASE174_DEPLOY_STATUS=$?
printf 'phase174_deploy_status=%s\n' "$PHASE174_DEPLOY_STATUS"
cat "$PHASE174_ROOT/deployment.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE174_ROOT/deployment/result.json"
```

仍须核对替换、归属、基线字节和构建结果，不能只读退出码。

## 4. 采集新观察及上下文

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE174_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE174_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE174_ROOT/observation.log" 2>&1
PHASE174_OBSERVATION_STATUS=$?
printf 'phase174_observation_status=%s\n' "$PHASE174_OBSERVATION_STATUS"
cat "$PHASE174_ROOT/observation.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE174_ROOT/deployment/plan.json" \
  --observation "$PHASE174_ROOT/observation/result.json" --clang "$PHASE174_CLANG" \
  --output "$PHASE174_ROOT/context-bridge" --timeout-seconds 600 \
  > "$PHASE174_ROOT/context-bridge.log" 2>&1
PHASE174_CONTEXT_STATUS=$?
printf 'phase174_context_status=%s\n' "$PHASE174_CONTEXT_STATUS"
cat "$PHASE174_ROOT/context-bridge.log"
```

## 5. 自动采集合同输入及测试入口上下文

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" inspect-contracts \
  --context "$PHASE174_ROOT/context-bridge/result.json" \
  --observation "$PHASE174_ROOT/observation/result.json" --clang "$PHASE174_CLANG" \
  --output "$PHASE174_ROOT/contracts-static" --timeout-seconds 600 \
  > "$PHASE174_ROOT/contracts-static.log" 2>&1
PHASE174_CONTRACT_STATUS=$?
printf 'phase174_contract_status=%s\n' "$PHASE174_CONTRACT_STATUS"
cat "$PHASE174_ROOT/contracts-static.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE174_ROOT/contracts-static/result.json"
```

检查 `entryContexts`、`entryInputGaps`、`declarationJoins`、`graphs`、`dataModels`、
`relocationContracts` 和 `stages`。不唯一生产者、未建模归档/外部提供者、未知调用、
类型或原生数据模型不匹配均须保留。不要改动捕获参数来压过失败；提供相应入口的
`entry-000/run-status.json` 等诊断。

## 6. 在支持的宿主机采集诊断映射身份

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" capture-runtime \
  --observation "$PHASE174_ROOT/observation/result.json" \
  --output "$PHASE174_ROOT/runtime-identity" --timeout-seconds 600 \
  > "$PHASE174_ROOT/runtime-identity.log" 2>&1
PHASE174_RUNTIME_STATUS=$?
printf 'phase174_runtime_status=%s\n' "$PHASE174_RUNTIME_STATUS"
cat "$PHASE174_ROOT/runtime-identity.log"
```

若失败，先提供该日志和 `runtime-identity/trace/capture.json`，不检查不存在的结果，
也不将该采集视为完成。静态报告保留，但运行身份目标仍未完成。

若成功：

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE174_ROOT/runtime-identity/result.json"
```

核对 `requiredMappedImagesVerified`、`mappedEndpointOccurrencesVerified`、
`metadataCompatibleProviderEvents`、`mappingCaptureFailures`、未解析行及各事件的
特殊合同。计数取决于实际运行，不能硬编码为此前的 301/602。
`untracedRuntimeBindingClosureComplete` 继续 false。

## 7. 复用原合同输入，关联新运行证据

仅在上一步成功时执行：

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" refine-contracts \
  --input "$PHASE174_ROOT/contracts-static/result.json" \
  --runtime "$PHASE174_ROOT/runtime-identity/result.json" \
  --output "$PHASE174_ROOT/contracts-with-runtime" \
  > "$PHASE174_ROOT/contracts-with-runtime.log" 2>&1
PHASE174_REFINE_STATUS=$?
printf 'phase174_refine_status=%s\n' "$PHASE174_REFINE_STATUS"
cat "$PHASE174_ROOT/contracts-with-runtime.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE174_ROOT/contracts-with-runtime/result.json"
```

## 8. 明确源端运行配置后进行有限程序观察比较

这一阶段需要**真实的源端可执行文件及其运行方式**。现有目标报告不能可靠推出
源端启动器、sysroot、种子或实验输入；不要猜测路径。使用已成功执行的源端基线
文件，保留其真实参数和来源。以下文件描述的是调用输入，不是已证明的内部对象域。

先设置实际的源程序、启动器和源工作目录，例如使用原实验中的既有变量：

```bash
: "${SOURCE_BASELINE_EXE:?请设置实际源端基线可执行文件}"
: "${SOURCE_RUNNER:?请设置实际源端运行器，例如原实验使用的 qemu-riscv64}"
: "${SOURCE_RUN_CWD:?请设置实际源端运行工作目录}"
export SOURCE_BASELINE_EXE SOURCE_RUNNER SOURCE_RUN_CWD
```

生成可检查的调用输入描述。这里选择与原目标实验一致的显式受控环境；若原源端
实验使用不同环境或参数，须根据原执行记录在该文件中明确给出，不能假定已复现。

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['PHASE174_ROOT'])
deployment=json.loads((root/'deployment/plan.json').read_text())
value={'schemaVersion':'riscv2x86.native-process-input-domain.v1',
       'sourceDirectory':os.environ['SOURCE_RUN_CWD'],
       'sourceEnvironment':deployment['environment'],
       'arguments':[], 'expectedExitCodes':[0], 'inputFiles':[]}
with (root/'invocation-domain.json').open('x') as stream:
    json.dump(value,stream,indent=2);stream.write('\n')
print(root/'invocation-domain.json')
PY
```

核对参数、退出域和环境后生成计划。若原运行器需要 `-L <sysroot>`，请按原记录
追加 `--launcher-arg=-L --launcher-arg="$SOURCE_SYSROOT"`；未使用时不要添加。

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" prepare-comparison \
  --deployment "$PHASE174_ROOT/deployment/result.json" \
  --source-program "$SOURCE_BASELINE_EXE" --source-machine 243 \
  --source-launcher "$SOURCE_RUNNER" --domain "$PHASE174_ROOT/invocation-domain.json" \
  --output "$PHASE174_ROOT/process-comparison-plan.json" --timeout-seconds 600
```

源运行器与源程序均被摘要绑定；存在运行器不意味着其源执行机制已经证明。没有该
输入时，步骤 8 保留待办，不得填写虚构源程序来得到成功。stdin 固定为 `/dev/null`，
只比较声明参数下的进程退出码和输出字节。内部随机输入是否一致、外部文件效果、
内存对象和候选覆盖均不由此证明。正常/故障终止在不同执行机制间的语义对应也需
独立合同，不能删除差异或自行重编码退出码。

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" compare-programs \
  --plan "$PHASE174_ROOT/process-comparison-plan.json" \
  --output "$PHASE174_ROOT/process-comparison" > "$PHASE174_ROOT/process-comparison.log" 2>&1
PHASE174_COMPARE_STATUS=$?
printf 'phase174_compare_status=%s\n' "$PHASE174_COMPARE_STATUS"
cat "$PHASE174_ROOT/process-comparison.log"
```

```bash
python3 "$PHASE174_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE174_ROOT/process-comparison/result.json"
```

退出码 0 表示比较操作及证据生成完成，必须继续读取
`processObservableComparisonStatus`：`verified`、`failed` 或 `inconclusive`。
该状态不能替代 L1/L0–L3 或程序级语义批准。

可以再次用 `refine-contracts --comparison ...` 关联此报告。若已有运行证据，选择
`contracts-with-runtime/result.json` 为输入；否则使用 `contracts-static/result.json`。
指定全新的输出目录，`check` 继续重新派生所有关联结果。

## 开发验证与后续材料

本开发环境的真实 ptrace 测试因权限不可用跳过；不将其计为成功。
C/GCC 捕获、链接、进程比较、ELF/虚拟映像解析和回执篡改检查有实际测试；
模拟的 Clang/源证明边界均在测试注释中标明。宿主机 GMP 验证仍需执行以上流程。

下一步提供首个失败日志，或成功后的 `contracts-static/result.json`、运行身份报告
和有限比较结果。无需继续逐文件人工收集宏定义和构建输入；程序会沿回执链追溯。
任何阶段未支持或未证明的部分继续保留 `stages`/`entryInputGaps`/特殊合同，不以
“操作成功”宣告五项目标全部完成。

开发环境最终相关回归：**170 passed，4 skipped**。四项跳过分别涉及 ptrace、真实 Clang、RISC-V GCC/Clang 组合及完整原生翻译前端；均未计作通过。`git diff --check` 通过。

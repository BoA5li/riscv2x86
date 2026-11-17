# Phase197：规范类型、整组操作数关系及重复复核开销

本轮继续使用原 Pipeline、Phase6 证明、渲染、回填和原评估器。修复的是证据传递及复核实现，不增加另一条翻译路线。

- L2 声明载体优先采用编译器 `desugaredQualType`，缺少展开类型时使用原 AST typedef 解析器；原拼写及声明身份保留。声明和直接表达式的类型冲突仍拒绝。
- 表达式绑定使用整组 GNU 操作数关系，保留 `%r` 原约束、关系身份和允许交换顺序。结构绑定成功不等于交换语义证明成功。原标量 L2 尚无交换证明消费路径时明确报告 `L2_SCALAR_OPERAND_PERMUTATION_PROOF_REQUIRED`。
- 原八参数、指针和 void 函数没有凭此获得标量测试桩支持；仍可报告 harness、值流、对象和观察义务。
- readiness 增加完整标量/片段原因列表及实际声明身份。一个首要原因消失，不代表其他原因已消解。
- 同次原生输入检查读取每个路径一次，从实际字节计算摘要并复用为纯派生键；下一次调用仍重新读取。报告复核复用本次刚验证的上下文；公开回填入口和独立检查仍获取自己的上下文。

原始宏编辑权限、机器 ABI、内部对象访问、自然运行映像、规范实例覆盖、L3 等尚未闭合。源条件排除的实例继续保留，不计为已执行。

## 1. 更新与回归

工具目录必须是新目录；不要使用新版代码 resume 旧版结果。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE196_PARENT:?}"
export PHASE197_TOOLING="$PREP_ROOT/tooling-phase197"
git -C "$REPO" fetch origin phase197-typed-operand-closure
git -C "$REPO" worktree add --detach "$PHASE197_TOOLING" origin/phase197-typed-operand-closure
export PHASE197_PARENT="$(mktemp -d "$PHASE196_PARENT/phase197-XXXXXX")"
export PYTHONPATH="$PHASE197_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE197_CLI="$PHASE197_TOOLING/experiment/automate_native_project.py"
git -C "$PHASE197_TOOLING" rev-parse HEAD
printf 'PHASE197_PARENT=%s\n' "$PHASE197_PARENT"
```

执行定向与原框架回归。失败后先提供完整日志，不继续长实验。

```bash
bash -e <<'REGRESSION'
: "${PHASE197_TOOLING:?}" "${PHASE197_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE197_TOOLING/pytools/tests/test_phase197_typed_closure.py" \
 "$PHASE197_TOOLING/pytools/tests/test_phase196_readonly.py" \
 "$PHASE197_TOOLING/pytools/tests/test_phase196_original_context.py" \
 "$PHASE197_TOOLING/pytools/tests/test_program_claim_consumption.py" \
 "$PHASE197_TOOLING/pytools/tests/test_verification_session.py" \
 "$PHASE197_TOOLING/pytools/tests/test_ghidra_preflight.py" \
 "$PHASE197_TOOLING/pytools/tests/test_project_evidence_ledger.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE197_TOOLING/pytools/tests/test_wide_integer_original.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_project_diagnostic.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE197_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 "$PHASE197_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE197_TOOLING/pytools/tests/test_project_native_input.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_context_bridge.py" \
 "$PHASE197_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
 "$PHASE197_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE197_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 "$PHASE197_TOOLING/pytools/tests/test_automatic_batch_evaluation.py" \
 "$PHASE197_TOOLING/pytools/tests/test_automatic_l2_authority.py" \
 "$PHASE197_TOOLING/pytools/tests/test_l2_scalar_authority.py" \
 "$PHASE197_TOOLING/pytools/tests/test_l2_fragment_execution_authority.py" \
 "$PHASE197_TOOLING/pytools/tests/test_compiler_expression_contracts.py" \
 "$PHASE197_TOOLING/pytools/tests/test_compiler_expression_evaluation.py" \
 --basetemp="$PHASE197_PARENT/pytest" > "$PHASE197_PARENT/regression.log" 2>&1
cat "$PHASE197_PARENT/regression.log"
REGRESSION
```

## 2. 同配置新建实验，只到准备阶段

```bash
bash -e <<'PREPARE'
: "${PHASE196_PARENT:?}" "${PHASE197_PARENT:?}" "${PHASE197_CLI:?}"
status=0
python3 "$PHASE197_CLI" replan \
 --configuration "$PHASE196_PARENT/diagnostic/diagnostic-plan.json" \
 --output "$PHASE197_PARENT/diagnostic" --stop-after preparation \
 --profile-output "$PHASE197_PARENT/preparation-profile.json" \
 > "$PHASE197_PARENT/preparation.log" 2>&1 || status=$?
printf 'preparation_status=%s\n' "$status"
cat "$PHASE197_PARENT/preparation.log"
test "$status" -eq 1
PREPARE
```

退出 1 只有结合 paused、preparation 完成、无当前采集失败才符合预期。
此时先查看 originalLayerReadiness：scalarAuthorityReasonCodes、fragmentBoundaryReasonCodes 及 functionBindingDiagnostic。应保留 functionId/nativeCompilerDeclarationId，不再只有空身份表。
对于已提供规范整数类型的三个声明，原有 width=0 / VALUE_NODE_MISSING 应得到修复；若仍出现，应提供具体 operandSlotFacts 和 compilerExpressionFacts。其他候选不保证适用。
GNU % 输入应出现在完整关系中；不应再仅因单槽解析 %r 失败。后续出现交换证明、harness 或内部值流原因属于需要继续处理的真实义务。
L2 可能进一步报告真实的值流、边界、类型、执行合同或其他缺口；这些必须保留。
若原后端因更完整的编译器事实报告 unsupported/冲突，应保留失败目录和原 attempt 原因，不得恢复独立整数路线或忽略新增事实。

重点比较相同命令范围内的墙钟时间、check_input 调用次数、native-input.validate-artifacts、pure.key.*、snapshot 和 binding.derive。无缓存只读冻结开销及剩余递归复核尚未全部优化，不承诺固定加速比。
没有复制事件的内部只读命中不等于省略了文件验证。总耗时及调用次数须结合看，不能相加嵌套 inclusiveSeconds。

## 3. 继续快速诊断，再空会话复核

准备阶段成功后继续；当前旧计划选择 [0]，仍保留未选用例 [1]。

```bash
bash -e <<'DIAGNOSTIC'
: "${PHASE197_PARENT:?}" "${PHASE197_CLI:?}"
status=0
python3 "$PHASE197_CLI" resume --output "$PHASE197_PARENT/diagnostic" \
 --profile-output "$PHASE197_PARENT/resume-profile.json" \
 > "$PHASE197_PARENT/resume.log" 2>&1 || status=$?
printf 'resume_status=%s\n' "$status"
cat "$PHASE197_PARENT/resume.log"
test "$status" -eq 1
python3 "$PHASE197_CLI" check --input "$PHASE197_PARENT/diagnostic/progress.json" \
 --verification-cache-mib 0 --profile-output "$PHASE197_PARENT/check-no-cache-profile.json" \
 > "$PHASE197_PARENT/check-no-cache.log" 2>&1
python3 "$PHASE197_CLI" ledger --input "$PHASE197_PARENT/diagnostic/progress.json" \
 --profile-output "$PHASE197_PARENT/ledger-profile.json" > "$PHASE197_PARENT/evidence-ledger.json"
DIAGNOSTIC
```

预计完整义务仍未全部消解，semanticApproval=false。claimConsumption 应区分已检查的有限子结论与 missingProofFacts；它不是新增的通过标准。

## 4. 可选的同范围性能对照

仅在上述检查成功、需要量化优化时执行另一遍相同 check。与无缓存 check 比较同一输出、相同检查器调用范围；不要直接比较 resume 和 check。

```bash
python3 "$PHASE197_CLI" check --input "$PHASE197_PARENT/diagnostic/progress.json" \
 --verification-cache-mib 256 --profile-output "$PHASE197_PARENT/check-cached-profile.json" \
 > "$PHASE197_PARENT/check-cached.log" 2>&1
```

缓存开关应得出相同诊断结论。文件系统缓存和主机负载影响时间，单次结果不直接作为论文稳定加速比。

## 正式评估与后续材料

原 formal 命令及完整 L0 矩阵不改。先核查本轮 L2 事实和剩余 missingProofFacts，再决定正式运行范围。
当前同一实例的源分支若仍排除，应如实保留该样本，并选择原项目支持的可执行配置或其他真实实例；增加随机次数无法补齐该覆盖依据。

请优先提供 regression.log、preparation.log、preparation-profile.json。继续执行后提供 resume.log、resume-profile.json、check-no-cache.log、check-no-cache-profile.json、evidence-ledger.json。
若准备阶段失败，提供 preparation.log 和 diagnostic/preparation/progress.json，以及日志指出的最新 attempt 目录中的原 backend-report / attempts / stderr；不要继续重复整个构建矩阵。

## 停止条件与应提供的信息

回归失败先停止。准备阶段采集失败也先停止，保留完整失败目录。准备成功后优先上传 preparation.log、preparation-profile.json；若 L2 原因仍需定位，上传新报告的 functions / compilerFragmentJoin / compilerExpressionEvaluation / approvalArtifact 及原 instance-bindings。

不要修改 GMP 阈值或通过增加随机次数弥补被条件排除实例的覆盖。当前应先验证修复和新原因，再选择原项目支持的真实可执行实例/配置，随后进入原正式评估。快速诊断不计作正式 L0–L3 通过。

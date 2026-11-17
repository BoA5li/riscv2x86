# Phase196：原 L2 事实衔接、只读派生复用和证据前提规则

基线：phase195-verification-profiling / 98b6cdf719917db7bce17f26356327fff29add36。

## 本轮修改与边界

1. 从原 automatic_batch_cli 提取共用的 AST 函数事实导出器。普通入口仍执行原编译器采集及筛选；native 入口使用已检查的冻结 AST 和精确的内联汇编所属函数。
2. 将已经 Clang Tooling 导出并通过物理实例绑定检查的 GNU 输出/输入分区与约束，加入派生 AST 视图；缺失字段才补充，显式冲突拒绝。原收据 AST 不修改。声明身份、物理范围及内容共同绑定，不用函数名称猜测实例，不删除 `%` 等约束。
3. 共用原 compiler_authority_report 和 materialize_automatic_l2_authority，保留函数/片段事实，并在授权物化后重建原 attempt archive，再调用原 candidate materializer。保留 backend-report.json；检查器重派生授权结果，原独立重跑继续生效。
4. 内部只读 AST/函数派生结果按操作复用，公共原生输入接口仍默认返回可修改副本。普通嵌套修改和重新初始化拒绝，显式 deepcopy 得到私有副本。只读容器是内部所有权约定，不是抵抗任意 Python 代码修改运行时的安全沙箱。
5. 新增 pure.key / pure.copy / pure.freeze / pure.derive 等计时，及实例绑定、物理投影计时。文件、工具、环境、依赖和收据检查继续执行；没有缓存整个“检查通过”结果。
6. program_claim_consumption 从原检查器已重新派生的有限事实建立子结论。整体义务通过明确的前提列表推导，ledger 展示已检查子结论及 missingProofFacts。仅有进程一致或机器盘点不满足完整义务。

本轮不承诺完整机器 ABI、函数内部对象访问、实际调用效果、自然运行映像、规范机器码覆盖或 L3 已闭合。源条件排除的实例继续保留，不能把它计为指令执行覆盖；不能通过修改 GMP 阈值强迫其执行。原始宏编辑权限仍为 false。

## 1. 更新与回归

工具目录必须是新目录；不要使用新版代码 resume 旧版结果。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE195_PARENT:?}"
export PHASE196_TOOLING="$PREP_ROOT/tooling-phase196"
git -C "$REPO" fetch origin phase196-original-evidence-context
git -C "$REPO" worktree add --detach "$PHASE196_TOOLING" origin/phase196-original-evidence-context
export PHASE196_PARENT="$(mktemp -d "$PHASE195_PARENT/phase196-XXXXXX")"
export PYTHONPATH="$PHASE196_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE196_CLI="$PHASE196_TOOLING/experiment/automate_native_project.py"
git -C "$PHASE196_TOOLING" rev-parse HEAD
printf 'PHASE196_PARENT=%s\n' "$PHASE196_PARENT"
```

执行定向与原框架回归。失败后先提供完整日志，不继续长实验。

```bash
bash -e <<'REGRESSION'
: "${PHASE196_TOOLING:?}" "${PHASE196_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE196_TOOLING/pytools/tests/test_phase196_readonly.py" \
 "$PHASE196_TOOLING/pytools/tests/test_phase196_original_context.py" \
 "$PHASE196_TOOLING/pytools/tests/test_program_claim_consumption.py" \
 "$PHASE196_TOOLING/pytools/tests/test_verification_session.py" \
 "$PHASE196_TOOLING/pytools/tests/test_ghidra_preflight.py" \
 "$PHASE196_TOOLING/pytools/tests/test_project_evidence_ledger.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE196_TOOLING/pytools/tests/test_wide_integer_original.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_project_diagnostic.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE196_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 "$PHASE196_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE196_TOOLING/pytools/tests/test_project_native_input.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_context_bridge.py" \
 "$PHASE196_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
 "$PHASE196_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE196_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 "$PHASE196_TOOLING/pytools/tests/test_automatic_batch_evaluation.py" \
 "$PHASE196_TOOLING/pytools/tests/test_automatic_l2_authority.py" \
 "$PHASE196_TOOLING/pytools/tests/test_l2_scalar_authority.py" \
 "$PHASE196_TOOLING/pytools/tests/test_l2_fragment_execution_authority.py" \
 "$PHASE196_TOOLING/pytools/tests/test_compiler_expression_contracts.py" \
 "$PHASE196_TOOLING/pytools/tests/test_compiler_expression_evaluation.py" \
 --basetemp="$PHASE196_PARENT/pytest" > "$PHASE196_PARENT/regression.log" 2>&1
cat "$PHASE196_PARENT/regression.log"
REGRESSION
```

## 2. 同配置新建实验，只到准备阶段

```bash
bash -e <<'PREPARE'
: "${PHASE195_PARENT:?}" "${PHASE196_PARENT:?}" "${PHASE196_CLI:?}"
status=0
python3 "$PHASE196_CLI" replan \
 --configuration "$PHASE195_PARENT/diagnostic/diagnostic-plan.json" \
 --output "$PHASE196_PARENT/diagnostic" --stop-after preparation \
 --profile-output "$PHASE196_PARENT/preparation-profile.json" \
 > "$PHASE196_PARENT/preparation.log" 2>&1 || status=$?
printf 'preparation_status=%s\n' "$status"
cat "$PHASE196_PARENT/preparation.log"
test "$status" -eq 1
PREPARE
```

退出 1 只有结合 paused、preparation 完成、无当前采集失败才符合预期。
此时先核对新增函数表及 functionBindingDiagnostic。实际存在可导出的函数时不应继续报告函数表完全缺失。
L2 可能进一步报告真实的值流、边界、类型、执行合同或其他缺口；这些必须保留。
若原后端因更完整的编译器事实报告 unsupported/冲突，应保留失败目录和原 attempt 原因，不得恢复独立整数路线或忽略新增事实。

重点读取 profile：native-input._native_graph、native-input.mutable-result-copy、original-compiler-functions.v1 命中记录，以及 native-original.frontend-projection / compiler_native_instance_binding.derive。
没有复制事件的内部只读命中不等于省略了文件验证。总耗时及调用次数须结合看，不能相加嵌套 inclusiveSeconds。

## 3. 继续快速诊断，再空会话复核

准备阶段成功后继续；当前旧计划选择 [0]，仍保留未选用例 [1]。

```bash
bash -e <<'DIAGNOSTIC'
: "${PHASE196_PARENT:?}" "${PHASE196_CLI:?}"
status=0
python3 "$PHASE196_CLI" resume --output "$PHASE196_PARENT/diagnostic" \
 --profile-output "$PHASE196_PARENT/resume-profile.json" \
 > "$PHASE196_PARENT/resume.log" 2>&1 || status=$?
printf 'resume_status=%s\n' "$status"
cat "$PHASE196_PARENT/resume.log"
test "$status" -eq 1
python3 "$PHASE196_CLI" check --input "$PHASE196_PARENT/diagnostic/progress.json" \
 --verification-cache-mib 0 --profile-output "$PHASE196_PARENT/check-no-cache-profile.json" \
 > "$PHASE196_PARENT/check-no-cache.log" 2>&1
python3 "$PHASE196_CLI" ledger --input "$PHASE196_PARENT/diagnostic/progress.json" \
 --profile-output "$PHASE196_PARENT/ledger-profile.json" > "$PHASE196_PARENT/evidence-ledger.json"
DIAGNOSTIC
```

预计完整义务仍未全部消解，semanticApproval=false。claimConsumption 应区分已检查的有限子结论与 missingProofFacts；它不是新增的通过标准。

## 4. 可选的同范围性能对照

仅在上述检查成功、需要量化优化时执行另一遍相同 check。与无缓存 check 比较同一输出、相同检查器调用范围；不要直接比较 resume 和 check。

```bash
python3 "$PHASE196_CLI" check --input "$PHASE196_PARENT/diagnostic/progress.json" \
 --verification-cache-mib 256 --profile-output "$PHASE196_PARENT/check-cached-profile.json" \
 > "$PHASE196_PARENT/check-cached.log" 2>&1
```

缓存开关应得出相同诊断结论。文件系统缓存和主机负载影响时间，单次结果不直接作为论文稳定加速比。

## 正式评估与后续材料

原 formal 命令及完整 L0 矩阵不改。先核查本轮 L2 事实和剩余 missingProofFacts，再决定正式运行范围。
当前同一实例的源分支若仍排除，应如实保留该样本，并选择原项目支持的可执行配置或其他真实实例；增加随机次数无法补齐该覆盖依据。

请优先提供 regression.log、preparation.log、preparation-profile.json。继续执行后提供 resume.log、resume-profile.json、check-no-cache.log、check-no-cache-profile.json、evidence-ledger.json。
若准备阶段失败，提供 preparation.log 和 diagnostic/preparation/progress.json，以及日志指出的最新 attempt 目录中的原 backend-report / attempts / stderr；不要继续重复整个构建矩阵。

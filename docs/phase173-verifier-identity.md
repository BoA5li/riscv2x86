# Phase173：验证器身份、跨 worktree 回执与实验重跑

本轮修复 phase172 在新 worktree 检查旧审计回执时出现的
`DEPLOYMENT_AUDIT_VERIFIER_CHANGED`。本轮不宣告 ABI、合法对象、输出终止合同或
程序级 L0–L3 验证已经完成。

## 实现与严格边界

新版审计前置回执为 `riscv2x86.deployment-candidate-audit.v2`。

- 验证器身份由包内相对路径、源码摘要、清单策略和 schema 构成，安装绝对路径另作
  `verifierProvenance` 保存。相同源码位于不同 worktree 不再导致身份不同。
- 保守绑定整个 `riscv2x86_py` 包的 Python 源码清单。增加、删除或修改任何源码，
  包括间接辅助模块，均要求重新审计。这里故意不只绑定原来的三个入口文件。
- 验证策略变化同样导致失效；审计前后比较清单，拒绝在审计过程中发生源码变化。
- 拒绝混合加载不同包目录的模块，以及可能造成源码清单遗漏的符号链接。
- 原有候选摘要、构建产物、工具摘要、独立重建结果、绑定和部署检查继续执行。
- 原生上下文检查增加观察回执预检：在昂贵的目标输入采集前发现不兼容的旧审计链。
- 新增 `check-audit`，可单独验证审计前置回执，不必等部署后才发现其失效。

该源码清单不声称覆盖 Python 标准库、解释器和所有外部运行环境。已有外部候选工具
仍按原回执检查；整个机制检查证据一致性，不是对不可信采集主机的密码学认证。
审计目录、候选和实验产物仍须满足原有位置、摘要和依赖约束，本轮仅允许验证器
源码在不同安装目录之间按内容核对，不允许任意搬迁或修改实验产物。

## 为什么本次仍要重新审计和部署

phase171/172 的 v1 回执只绑定三个文件，无法证明完整包内验证依赖未变化。
新版不会把旧回执去掉路径后直接升级为更强的证据，而会明确报出：

`DEPLOYMENT_AUDIT_LEGACY_VERIFIER_SCOPE_REAUDIT_AND_REDEPLOY_REQUIRED`

因此本次必须形成新的审计、部署、观察证据链。以后两个 worktree 的新版包源码
完全相同，才可以核对同一份 v2 审计回执。若代码或清单策略变化，仍须重新审计。
不要编辑旧回执的 schema、路径、摘要或完成标志，不要用 diagnostic-only 绕过门槛。

## 分步执行

在原 `.venv-l2` 终端中逐步执行。**每一步退出码为 0 后再执行下一步**；失败时保留
该步骤日志。不要对尚未生成的 `result.json` 执行后续检查。
原 phase171/172 结果全部保留。以下路径从已有变量和计划推导，不使用 `/deployment`
或 `/observation` 这类根目录路径。

### 1. 更新工具并创建新实验目录

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE171_ROOT:?}" "${PHASE172_ROOT:?}"
git -C "$REPO" fetch origin phase173-verifier-identity
export PHASE173_TOOLING="$PREP_ROOT/tooling-phase173"
git -C "$REPO" worktree add --detach "$PHASE173_TOOLING" origin/phase173-verifier-identity
export PHASE173_ROOT="$(mktemp -d "$PHASE172_ROOT/phase173-XXXXXX")"
: "${PHASE173_ROOT:?}"
export PYTHONPATH="$PHASE173_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE173_PLAN="$PHASE171_ROOT/deployment/plan.json"
export PHASE173_CLANG="$(command -v clang-10)"
: "${PHASE173_CLANG:?clang-10 unavailable}"
git -C "$PHASE173_TOOLING" rev-parse HEAD
printf 'PHASE173_ROOT=%s\n' "$PHASE173_ROOT"
ls -lh -- "$PHASE173_PLAN"
```

若 tooling 目录已经存在，请使用一个新的 worktree 路径，不要覆盖已有 worktree。
如果第一步未成功创建目录或设置变量，应先处理该错误。

### 2. 回归测试

```bash
python3 -m pytest -q -rs \
  "$PHASE173_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE173_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_validation_cli.py" \
  "$PHASE173_TOOLING/pytools/tests/test_native_compiler_configuration.py" \
  --basetemp="$PHASE173_ROOT/pytest" \
  > "$PHASE173_ROOT/focused.log" 2>&1
PHASE173_TEST_STATUS=$?
printf 'phase173_test_status=%s\n' "$PHASE173_TEST_STATUS"
cat "$PHASE173_ROOT/focused.log"
```

应为退出码 0。测试包含显式模拟翻译证明边界的夹具，这些夹具不构成 GMP 翻译证明。
跨目录测试实际启动第二个 Python 进程，加载复制后的包检查同一份审计和部署回执；
随后修改间接辅助模块，验证旧回执被拒绝。

### 3. 在新工具下重新独立审计候选

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" audit-candidate \
  --plan "$PHASE173_PLAN" \
  --output "$PHASE173_ROOT/candidate-audit" --timeout-seconds 600 \
  > "$PHASE173_ROOT/candidate-audit.log" 2>&1
PHASE173_AUDIT_STATUS=$?
printf 'phase173_audit_status=%s\n' "$PHASE173_AUDIT_STATUS"
cat "$PHASE173_ROOT/candidate-audit.log"
```

退出码 0 后，检查新回执：

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" check-audit \
  --plan "$PHASE173_PLAN" \
  --input "$PHASE173_ROOT/candidate-audit/deployment-audit.json"
```

应得到 `auditPrerequisiteIntegrityChecked=true`。它表示审计前置证据有效，不表示
程序级语义批准。

### 4. 重新部署并检查

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" deploy \
  --plan "$PHASE173_PLAN" \
  --audit "$PHASE173_ROOT/candidate-audit/deployment-audit.json" \
  --output "$PHASE173_ROOT/deployment" --timeout-seconds 600 \
  > "$PHASE173_ROOT/deployment.log" 2>&1
PHASE173_DEPLOY_STATUS=$?
printf 'phase173_deploy_status=%s\n' "$PHASE173_DEPLOY_STATUS"
cat "$PHASE173_ROOT/deployment.log"
```

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE173_ROOT/deployment/result.json"
```

应看到 `deploymentMode=audited-local-candidate`，以及对应构建和替换证据。若基线字节
复现或归属检查未通过，应保留其阻塞，不能只依据退出码继续宣告部署验证完成。
新部署仍绑定原计划选择的候选，不需要修改原计划或旧部署的审计路径。

### 5. 对新部署采集 v3 观察并检查

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE173_ROOT/deployment/result.json" --diagnostic \
  --output "$PHASE173_ROOT/observation" --timeout-seconds 600 \
  > "$PHASE173_ROOT/observation.log" 2>&1
PHASE173_OBSERVATION_STATUS=$?
printf 'phase173_observation_status=%s\n' "$PHASE173_OBSERVATION_STATUS"
cat "$PHASE173_ROOT/observation.log"
```

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE173_ROOT/observation/result.json"
```

预期 schema 为 `riscv2x86.deployment-observation.v3`。核对实际返回码、预算、诊断
绑定及未验证端点，不能把观察采集完成等同于运行绑定闭包完成。

### 6. 关联新观察与真实编译上下文

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE173_ROOT/deployment/plan.json" \
  --observation "$PHASE173_ROOT/observation/result.json" \
  --clang "$PHASE173_CLANG" --timeout-seconds 600 \
  --output "$PHASE173_ROOT/context-bridge" \
  > "$PHASE173_ROOT/context-bridge.log" 2>&1
PHASE173_CONTEXT_STATUS=$?
printf 'phase173_context_status=%s\n' "$PHASE173_CONTEXT_STATUS"
cat "$PHASE173_ROOT/context-bridge.log"
```

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE173_ROOT/context-bridge/result.json"
```

本次不再把旧 phase171 观察报告传给 phase173 的上下文采集。此处计划来自新部署，
与重新采集的观察严格对应。预期能产生完整报告；对于此前给出的源码关系，
`sourceContentLineageVerified` 应由检查得出为 true，`targetNativeInputAcquired=true`。
其他合同未证明时继续为 false，且保留 `obligations`。

### 7. 独立部署重建

```bash
python3 "$PHASE173_TOOLING/experiment/advance_native_closure.py" replay \
  --input "$PHASE173_ROOT/deployment/result.json" \
  --output "$PHASE173_ROOT/deployment-replay" --timeout-seconds 600 \
  > "$PHASE173_ROOT/deployment-replay.log" 2>&1
PHASE173_REPLAY_STATUS=$?
printf 'phase173_replay_status=%s\n' "$PHASE173_REPLAY_STATUS"
cat "$PHASE173_ROOT/deployment-replay.log"
```

应核对 `independentDeploymentRebuildComplete=true`，该结论仍不等于程序语义批准。

## 失败处理与验收

若任一步失败，提供该步骤日志和已经生成的 run-status；不要重用失败输出目录，
也不要删除或篡改旧证据。若提示内容或策略变化，先核对工具源码；在确定版本后
重新建立审计及部署链。

本轮修复验收条件是：新版相同源码能跨工具目录核对审计回执，实际源码/策略变化
仍被拒绝，且新审计→部署→观察→上下文报告→检查这条 GMP 流程能完成。
开发环境的回归通过不能替代最后一项真实实验验收。

完整自然运行绑定身份、ABI 与可变参数、对象生命周期/边界/别名、输出终止关系、
候选实例覆盖和通用 L0–L3 接入仍按 phase172 的剩余合同方案推进。

## 开发环境验证记录

相关回归：**123 passed，3 skipped**；`git diff --check` 通过。
跳过项分别需要真实 Clang、RISC-V GCC 加 Clang，以及完整原生翻译前端/工具链。
本开发环境没有你的 GMP 构建产物，因此最终实验验收须执行上面的宿主机流程。

# Phase190：自动化工作链的检查点与失败恢复

基于 Phase189（184f88a）。复用原翻译、证明、渲染、回填、独立候选重跑、
原评估器及原 L0 矩阵；本轮只修订编排、证据绑定和实验指南，不增加翻译路线。

## 修订内容

- 开始执行前冻结 bundle、工程记录、目标计划、QEMU、Ghidra 启动器、用例、
  超时及当前验证器身份。失败后不用重新手工拼接命令或重新翻译已检查候选。
- 顺序保存 `original → project → request → evaluation` 四个检查点。
  每个检查点必须通过其原检查器，并与冻结计划、前序产物及本次尝试路径对应。
- 恢复时重新检查已登记收据、工具和输入；有文件但未登记为检查点的中断产物
  不复用。失败目录保留，新尝试另建目录；同一输出禁止并发写入。
- 请求、验证计划及环境配置可在不执行、不覆盖文件的情况下重新派生检查。
  配套文件的字段或字节发生变化都拒绝复用。
- 有效的 `failed` / `inconclusive` 原评估是已完成的实验结果。`resume` 不会
  抹掉结果或不停重试直到通过；修改代码、用例或合同必须用新输出目录。
- 修正 Phase189 指南中的变量作用域：变量要在当前终端导出，不能指望子 Shell
  中的 `export` 影响后面的独立命令块。也修正目标计划通过符号链接选择时的路径绑定。

这些检查验证记录一致性与可复用性，不是独立程序级语义证明。
原始宏编辑权限、完整机器 ABI、内部对象访问、规范实例指令覆盖和完整程序
L2/L3 证据仍按原有边界报告缺失；不会因恢复成功而提升批准状态。

## 1．在当前终端更新并设置变量

下面的 `export` 直接在当前终端执行。仅 fetch/worktree 操作进入子 Shell。
新工作树和输出目录必须尚不存在。旧 Phase189 输出没有本轮检查点协议，不能直接恢复。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE190_TOOLING="$PREP_ROOT/tooling-phase190"
export PHASE190_PARENT="$(mktemp -d "$PHASE188_ROOT/phase190-XXXXXX")"
: "${PHASE190_PARENT:?}"
export PYTHONPATH="$PHASE190_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE190_CLI="$PHASE190_TOOLING/experiment/automate_native_project.py"

bash -e <<'SETUP_PHASE190'
: "${REPO:?}" "${PHASE190_TOOLING:?}" "${PHASE190_PARENT:?}"
git -C "$REPO" fetch origin phase190-campaign-checkpoints
git -C "$REPO" worktree add --detach "$PHASE190_TOOLING" origin/phase190-campaign-checkpoints
git -C "$PHASE190_TOOLING" rev-parse HEAD
printf 'PHASE190_PARENT=%s\n' "$PHASE190_PARENT"
SETUP_PHASE190
```

## 2．运行定向回归

```bash
bash <<'TEST_PHASE190'
: "${PHASE190_TOOLING:?}" "${PHASE190_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE190_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE190_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE190_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 "$PHASE190_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE190_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
 "$PHASE190_TOOLING/pytools/tests/test_evaluation_runner.py" \
 "$PHASE190_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE190_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 --basetemp="$PHASE190_PARENT/pytest" > "$PHASE190_PARENT/focused.log" 2>&1
status=$?
printf 'focused_status=%s\n' "$status"
cat "$PHASE190_PARENT/focused.log"
exit "$status"
TEST_PHASE190
```

测试成功后再执行真实工程实验。协议 fixture 或跳过的工具链集成不代表真实 GMP 通过。

## 3．单命令启动真实实验

无需手工创建 EvaluationRequest 或重新编写编译、链接、加载器和日志比较脚本。
继续使用已有的真实 bundle、底层构建记录和已确认的 RISC-V runtime prefix。

```bash
bash <<'RUN_PHASE190'
: "${PHASE190_CLI:?}" "${PHASE190_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE190_CLI" run \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 \
 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 1000 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC \
 --timeout-seconds 600 \
 --output "$PHASE190_PARENT/campaign" > "$PHASE190_PARENT/campaign-first.log" 2>&1
status=$?
printf 'campaign_status=%s\n' "$status"
cat "$PHASE190_PARENT/campaign-first.log"
exit "$status"
RUN_PHASE190
```

退出码仍为：`0` 原请求 verified；`1` 原评估完成但未 verified；`2` 编排或输入异常。
原 L0 若不通过，就不会越过它执行后续 L1。L1 采集输出一致也不会补造缺失的机器、
对象或规范覆盖证明；本次请求最终仍可能合理地返回 inconclusive。

GMP `0`、`1` 是随机播种开关，不是本 profile 可用的固定种子。
重复次数参数不保证双端内部生成的输入序列及迭代数已经对应，相关义务仍保留。

## 4．自动恢复或检查

同一版本、同一工作树下恢复，无需再次输入 bundle、路径、种子和工具参数：

```bash
python3 "$PHASE190_CLI" resume --output "$PHASE190_PARENT/campaign" \
 > "$PHASE190_PARENT/campaign-resume.log" 2>&1
PHASE190_STATUS=$?
printf 'resume_status=%s\n' "$PHASE190_STATUS"
cat "$PHASE190_PARENT/campaign-resume.log"
```

检查记录而不执行翻译、构建或测试：

```bash
python3 "$PHASE190_CLI" check --input "$PHASE190_PARENT/campaign/progress.json"
```

`check` 的返回 0 表示记录可检查，不等于验证通过。CLI 摘要包含：

- `completedStages`：已登记并检查的阶段前缀；
- `primaryFailure`：异常发生阶段及原因；
- `resultPaths`：实际收据位置，无需猜测目录；
- `originalEvaluation`：原评估器的逐尝试和层级摘要，不另行计算批准。

根目录保存 `campaign-plan.json`、`progress.json` 和 `attempts/`。
每次尝试独占目录；原工具的 `run-status.json`、stdout/stderr、重放记录和矩阵产物
保留在对应尝试目录。原阶段成功收据存储位置通过 `resultPaths` 给出。

有正常 failed/inconclusive 结果时，先分析结果；不要用 resume 期待它变成 verified。
若原输入、工具、配置或已登记证据变化，恢复会拒绝；不能修改哈希或删除检查点绕过。
修订代码后重新建输出目录，保留旧实验。

## 下一轮需要提供

请提供 `campaign-first.log`（若恢复过，再提供 `campaign-resume.log`）和
`campaign/progress.json`。若已完成 evaluation，再提供 `resultPaths.evaluation`
指向的适配器 `result.json`，以及同目录的 `evaluation-result.json`。
只有已生成的文件才需要提供，不要继续检查不存在的下游收据。

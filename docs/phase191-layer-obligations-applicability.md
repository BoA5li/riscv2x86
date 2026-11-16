# Phase191：实例适用性、分层义务与快速诊断

基于 Phase190 的真实自动化链，继续使用原 Pipeline、Phase6 证明与渲染、
原回填及独立重跑、`evaluation.run_evaluation` 和原 18 格 L0 矩阵。
本轮没有新增翻译路线，没有宣布整个 GMP 的 ABI、对象或 L2/L3 已闭合。

## 本轮改变和边界

1. 原候选的编辑范围、源码字节及编译器 AST 绑定后，分析包围实例的条件。
   只对编译器识别的整数文字量常量查询生成源端及目标端静态断言，验证宽度、
   符号和查询值。未知表达式或非结构化跳转保持未知，不根据函数名或助记符判断。
   结果 `excluded-under-compiler-query-contracts` 仅是受限源条件证据；
   `canonicalMachineDisposition` 仍是 `unknown`，不能据此宣布机器码消除或覆盖完成。
2. 按原评估层级区分 L1 前置条件、L1 运行后观察、L2 义务和最终独立审计。
   L2 与最终审计不再混在 L1 原因列表里，但完整义务清单始终保留。
   输出一致只记为有限过程观察；未接入真实证明生产者的 ABI、对象、输入对应等
   义务仍未消解，L1 仍可能为 inconclusive。不会接受调用者注入的通过布尔值。
3. 调用原 L2 authority 消费者报告实际不就绪原因；这不是 L2 执行结果，
   也没有伪造函数绑定来注册可运行的 L2 提供者。L3 仍需明确意图合同。
4. 同一请求检查内复用同一工程收据的验证结果，并逐次校验快照；不跨运行缓存。
   新增阶段、命令和层级耗时，避免再以 timeout 猜测实际运行时间。
5. GMP 快速诊断默认重复参数改为 10，可显式选择 1000。
   不改变 GMP 源码、尺寸覆盖条件或 18 格 L0 矩阵，不减少计划样本分母。

GMP `t-powm` 中，参数 10 在 REPFACTOR=1 下对应主体最少 11 次循环，
尺寸覆盖不足时继续循环；另有 small_2pow 检查。因此不是严格固定 10 组输入。
它能减少部分 L1 工作，但不能保证总时间缩短 100 倍，构建、审计和覆盖条件可能占主导。
报告应明确参数，不将这个快速配置写成“默认 1000 次官方完整配置已通过”。
相同随机种子也不能直接替代双端输入序列对应证明。

## 1. 设置新工作树

直接在当前终端执行 export。新验证器不能复用旧 Phase190 的已检查进度；
可以继续使用旧的原始 bundle、构建记录及输入元数据。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE191_TOOLING="$PREP_ROOT/tooling-phase191"
export PHASE191_PARENT="$(mktemp -d "$PHASE188_ROOT/phase191-XXXXXX")"
export PYTHONPATH="$PHASE191_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE191_CLI="$PHASE191_TOOLING/experiment/automate_native_project.py"
bash -e <<'SETUP'
: "${REPO:?}" "${PHASE191_TOOLING:?}"
git -C "$REPO" fetch origin phase191-layer-obligations-applicability
git -C "$REPO" worktree add --detach "$PHASE191_TOOLING" origin/phase191-layer-obligations-applicability
git -C "$PHASE191_TOOLING" rev-parse HEAD
SETUP
```

## 2. 定向回归

```bash
bash <<'TEST'
: "${PHASE191_TOOLING:?}" "${PHASE191_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE191_TOOLING/pytools/tests/test_original_source_applicability.py" \
 "$PHASE191_TOOLING/pytools/tests/test_project_obligation_assessment.py" \
 "$PHASE191_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE191_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE191_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 --basetemp="$PHASE191_PARENT/pytest" > "$PHASE191_PARENT/focused.log" 2>&1
status=$?
printf 'focused_status=%s\n' "$status"
cat "$PHASE191_PARENT/focused.log"
exit "$status"
TEST
```

测试中有明确模拟的编译器入口和候选绑定；它们不代表真实 GMP 实验通过。

## 3. 先自动执行到实例适用性检查点

```bash
bash <<'RUN'
: "${PHASE191_CLI:?}" "${PHASE191_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE191_CLI" run \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 10 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC --timeout-seconds 600 \
 --stop-after applicability --output "$PHASE191_PARENT/campaign" \
 > "$PHASE191_PARENT/campaign-first.log" 2>&1
status=$?
printf 'campaign_status=%s\n' "$status"
cat "$PHASE191_PARENT/campaign-first.log"
exit "$status"
RUN
```

预期检查点是 original、project、applicability，状态 paused，CLI 返回 1；
2 表示采集/输入异常。通过摘要的 resultPaths.applicability 读取实际 result.json：
查看 facts.instances、queries 和 layerReadiness，不要猜测目录。
若当前实例被源条件排除，它应保留在报告中；此实验不能证明该实例执行。
不要修改 GMP 阈值强行制造覆盖。需要从真实配置或其他真实实例选择后续覆盖样本。

## 4. 自动继续原 L0/L1 及计时

为复现本配置的原矩阵与过程观察，可直接继续同一冻结计划：

```bash
python3 "$PHASE191_CLI" resume --output "$PHASE191_PARENT/campaign" \
 > "$PHASE191_PARENT/campaign-resume.log" 2>&1
PHASE191_STATUS=$?
printf 'resume_status=%s\n' "$PHASE191_STATUS"
cat "$PHASE191_PARENT/campaign-resume.log"
python3 "$PHASE191_CLI" check --input "$PHASE191_PARENT/campaign/progress.json"
python3 "$PHASE191_CLI" timings --input "$PHASE191_PARENT/campaign/progress.json" \
 > "$PHASE191_PARENT/timings.json"
```

resume 重新检查已登记证据，保留前序检查点；正常 inconclusive 不会被无限重试。
L0 未 verified 就不会绕过它执行 L1。返回 0 表示原请求 verified，1 表示正常结果
未 verified，2 表示异常；check 返回 0 只表示证据记录一致。
计时使用单调时钟；阶段、层级、命令范围有嵌套，不要将所有行相加。
计时不覆盖全部独立复核开销；它不是可替代专门性能实验的基准测试。

需要默认 1000 配置时，重新创建输出目录，在首次 run 中改为 --repetitions 1000；
不要修改已冻结计划或将 10 配置的测量标记成 1000。

## 请提供的输出

- focused.log、campaign-first.log，以及恢复后的 campaign-resume.log；
- campaign/progress.json；resultPaths.applicability 指向的 result.json；
- 已生成的原 evaluation-result.json、obligation-assessment.json 和 timings.json。

下一步依据实际 source 分类与原 authority 拒绝原因推进：三端上下文、实际机器 ABI、
对象/调用效果、输入对应、自然加载身份、规范实例区域与运行事件，以及原 L2/L3 证据。
这些仍需真实生产者和独立检查器；本轮没有用静态条件或有限输出一致替代它们。

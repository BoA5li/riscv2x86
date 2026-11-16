# Phase194：真实工程快速诊断与原完整验证分开调度

基于 Phase193（0ec3bed）。本轮降低开发期间发现阻塞的成本，不减少最终验证义务。
只增加证据调度与重放检查；没有候选生成规则，也没有另一条翻译路线。

## 模式及正确性边界

`run` 默认仍为 `--mode formal`，调用原 `evaluation.run_evaluation`、原 18 格
L0 的参考构建与独立验证，以及原请求所需的后续层级。未通过的前层不会被绕过。

新增 `run --mode diagnostic`：

1. 原候选生成、回填和独立候选重跑 → 冻结真实工程 → 实例适用性/原 authority 就绪诊断；
2. 按记录的源端/目标端真实编译配置，各构建当前对象、动态库及测试入口；
3. **先采集当前双端机器事实**，不等待 18 格 L0 和 GMP 运行；
4. 对明确选择的用例调用原过程比较器，记录输出、退出、超时及加载器诊断；
5. 汇总实际采集异常、依赖阻塞、机器事实缺口及未闭合程序义务。

快速诊断没有执行完整矩阵，不会得到 L0/L1/L2/L3 verified；结果中
`formalMatrixCellsExecuted=0`、`formalValidationPerformed=false`、
`semanticApproval=false`。`diagnosticAcquisitionComplete=true` 只表示选定诊断节点
已取得可检查收据：即使过程输出不一致，也可能采集完成，须阅读 observations。
这不是“完整官方 GMP 测试通过”，也不能证明没有其余错误。

输入仍为同一真实 bundle 和编译器确认的实例。构建和重链接复用
native_project_evaluation；机器事实复用 Phase192 生产器；输出比较复用原 comparator。
未知 ABI、对象、调用效果、输入对应、自然运行身份、规范实例覆盖及程序审计仍保留。

## 检查点、失败和恢复

诊断节点为 `preparation`、`source-build`、`target-build`、`machine-inventory`，
以及每个选定的 `case-000000` 等节点。用例编号是固定计划的下标，不是源码种子编号。
当前一个 bundle 是一个工程输入，可含多个翻译实例；随机种子对应运行用例，两者不同。

- 两端构建互不依赖；源端失败仍尝试目标端。
- 机器事实与运行用例只依赖两端构建；机器事实失败不隐藏独立运行诊断。
- 一个用例的采集异常不阻止其他选定用例；真正缺少依赖的节点标为 blocked。
- 成功节点的收据、命令、环境、文件和输入身份在恢复前检查。没有登记检查点的
  中断产物不复用；每次重试使用新尝试目录，保留旧错误。
- 超时、域外退出和输出不一致若已形成完整收据，保留为终态，不用 resume 重试至通过。
- 恢复时不会重新翻译已检查候选、重建已完成一端或重跑已有用例。

本轮检查点粒度是“每端工程构建”和“每个用例”，不是每条编译命令。
完整矩阵仍由原调度执行；不使用诊断中的某个产物替代其独立验证产物。

## 1. 更新新工作树

本轮生产检查器源已变化，不用新代码恢复旧版本进度。继续复用底层真实 bundle、
构建记录和输入元数据。直接在当前终端 export，保持变量供后续命令使用。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE194_TOOLING="$PREP_ROOT/tooling-phase194"
export PHASE194_PARENT="$(mktemp -d "$PHASE188_ROOT/phase194-XXXXXX")"
export PYTHONPATH="$PHASE194_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE194_CLI="$PHASE194_TOOLING/experiment/automate_native_project.py"
bash -e <<'SETUP'
: "${REPO:?}" "${PHASE194_TOOLING:?}"
git -C "$REPO" fetch origin phase194-resumable-project-diagnostics
git -C "$REPO" worktree add --detach "$PHASE194_TOOLING" origin/phase194-resumable-project-diagnostics
git -C "$PHASE194_TOOLING" rev-parse HEAD
SETUP
```

## 2. 先运行定向回归

```bash
bash <<'TEST'
: "${PHASE194_TOOLING:?}" "${PHASE194_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE194_TOOLING/pytools/tests/test_native_project_diagnostic.py" \
 "$PHASE194_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE194_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE194_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 --basetemp="$PHASE194_PARENT/pytest" > "$PHASE194_PARENT/focused.log" 2>&1
status=$?
printf 'focused_status=%s\n' "$status"
cat "$PHASE194_PARENT/focused.log"
exit "$status"
TEST
```

协议测试明确模拟阶段生产者；集成测试使用真实 native ELF、构建和比较，但编译器实例
入口是模拟边界，不代表实际跨 ISA/GMP 验证完成。

## 3. 先取得机器事实，暂不等待运行用例

冻结两个运行用例（随机种子 42、43），诊断明确只选第 0 个。未选的第 1 个仍保留在
计划与摘要中。正式继续时使用两个用例，不会静默只执行诊断选中的那个。

```bash
bash <<'DIAGNOSE'
: "${PHASE194_CLI:?}" "${PHASE194_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE194_CLI" run --mode diagnostic \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 10 --diagnostic-case-indices 0 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC --timeout-seconds 600 \
 --stop-after machine-inventory --output "$PHASE194_PARENT/diagnostic" \
 > "$PHASE194_PARENT/diagnostic-first.log" 2>&1
status=$?
printf 'diagnostic_status=%s\n' "$status"
cat "$PHASE194_PARENT/diagnostic-first.log"
exit "$status"
DIAGNOSE
```

正常暂停预期返回 1，摘要 status=paused；2 表示存在采集异常。优先查看：

- currentAcquisitionFailures：当前未解决的采集错误；历史错误通过 resolved 区分；
- blockedStages：因依赖缺失而没有执行的节点；
- instanceApplicability、originalLayerReadiness：真实实例适用性和原层级准入缺失；
- machineFactGaps、unresolvedProgramObligations：事实/证明缺口，不能一概当作程序错误；
- resultPaths：实际收据路径，无需猜测尝试目录。

若希望更早暂停，可改为 `--stop-after preparation`；若希望一次完成选定诊断，去掉
--stop-after。其他可暂停节点为 source-build、target-build、实际选中的 case-XXXXXX。
初次执行仍包含原候选独立审计，不能承诺固定秒数或固定加速比。

## 4. 自动继续选定用例，并检查/导出诊断

已登记成功的节点不会重做。采集错误可修复环境后恢复；若修改代码、输入、工具或用例
合同，身份检查会拒绝复用，应保留旧实验并新建输出。

```bash
python3 "$PHASE194_CLI" resume --output "$PHASE194_PARENT/diagnostic" \
 > "$PHASE194_PARENT/diagnostic-resume.log" 2>&1
PHASE194_STATUS=$?
printf 'diagnostic_resume_status=%s\n' "$PHASE194_STATUS"
cat "$PHASE194_PARENT/diagnostic-resume.log"
python3 "$PHASE194_CLI" check --input "$PHASE194_PARENT/diagnostic/progress.json" \
 > "$PHASE194_PARENT/diagnostic-summary.json"
python3 "$PHASE194_CLI" timings --input "$PHASE194_PARENT/diagnostic/progress.json" \
 > "$PHASE194_PARENT/diagnostic-timings.json"
```

诊断执行无论正常暂停或正常采集完成，返回 1；采集异常返回 2。check 成功返回 0
只表示记录一致。不要把返回码或 acquisitionComplete 当作语义验证通过。
诊断 timings 返回经过检查的摘要，其中 operationTimings 包含阶段耗时，observations
含实际源/目标进程耗时。采集阶段计时包括内部检查，不能与嵌套进程耗时直接相加。

参数 10 保留 GMP 的尺寸覆盖条件，主体至少 11 次，可能继续运行；不是固定十组输入。
超时保留为证据不足，不因预算到期宣布通过。默认只选第一个运行用例；如需诊断两者，
在首次 run 中显式指定 `--diagnostic-case-indices 0,1`，不能修改已冻结计划。

## 5. 工作链稳定后执行原完整验证

对同一冻结合同，可继续原 preparation 子任务，复用已检查的原翻译/回填/候选审计。
正式步骤重新执行其正常构建、完整 18 格参考与独立验证，以及原请求的全部用例/层级；
不会使用诊断收据冒充 L0/L1 准入。

```bash
python3 "$PHASE194_CLI" formal --output "$PHASE194_PARENT/diagnostic" \
 > "$PHASE194_PARENT/formal.log" 2>&1
PHASE194_FORMAL_STATUS=$?
printf 'formal_status=%s\n' "$PHASE194_FORMAL_STATUS"
cat "$PHASE194_PARENT/formal.log"
python3 "$PHASE194_CLI" check \
 --input "$PHASE194_PARENT/diagnostic/preparation/progress.json"
python3 "$PHASE194_CLI" timings \
 --input "$PHASE194_PARENT/diagnostic/preparation/progress.json" \
 > "$PHASE194_PARENT/formal-timings.json"
```

正式执行返回 0 为原请求 verified，1 为正常未 verified，2 为异常。原 L1 未闭合就不
绕过它执行后续层级。程序级 ABI、内部对象、规范覆盖等仍需相应生产者与独立检查器。
不要期望重复 formal 会自行补齐这些能力；正常 inconclusive 会被保留。

正式阶段使用本计划冻结的两个用例和参数 10，不能标记为参数 1000 的默认官方运行。
若最终实验合同要求 1000、不同用例或配置，应新建明确的正式计划：run 默认 formal，
使用对应 --gmp-seeds / --repetitions 参数。不能修改旧计划或混合两种实验结论。

诊断父进度保持原诊断身份，正式进度另见命令返回的 formalProgressPath。
继续正式阶段后，原诊断证据仍可检查；它只绑定不可变前序收据，不冻结可继续的子进度文件。

## 请先提供

focused.log、diagnostic-first.log、已有的 diagnostic-resume.log、diagnostic-summary.json、
diagnostic-timings.json。若需要深入分析，再根据 resultPaths 提供机器和用例收据。
当前不必先开展完整矩阵，才能定位快速模式已经明确报告的阻塞。

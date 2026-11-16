# Phase195：操作内纯计算复用、分项计时和原证据诊断

本分支基于 phase194 的 28da8e250eec08e43ead879faebcb660b5cd37c9。
**本次托管编辑环境无法执行 Python、编译器或 pytest。新增实现及测试尚未运行；
不得将以前的 84 个测试通过记录当成本分支通过记录。先执行下面的回归。**

## 修改范围和结论边界

- 新增 verification_session：只缓存当前字节决定的 AST 规范化、盘点及 JSON 值身份。
  每次仍读取、散列并校验当前文件；工具、依赖、收据和完整检查器没有结果缓存。
  返回可变结构隔离复制；异常不缓存；预算限制的是保留结果的估算大小，
  不包括输入、深拷贝临时量和 Python 进程的全部内存。
- 每次 CLI 调用创建空会话，退出释放缓存。独立 check 使用新进程、空会话；
  可以用 --verification-cache-mib 0 完全禁用纯计算复用。
- 增加整体操作墙钟、嵌套检查耗时、调用及失败次数、命中/未命中、预算跳过及淘汰计数。
  wallSeconds 包括该操作中的生产、复核及结果输出，不含 Python 启动、参数解析和 profile 写盘。
  inclusiveSeconds 相互嵌套，不能相加当作总时间；exclusiveSeconds 排除了已计时的子调用。
- 原 campaign 在暂停前发布最终控制状态并完整检查一次，消除相邻重复复核。
  完整阶段检查、原翻译、原矩阵、独立重跑及失败保留规则继续适用。
- L2 functionBindingDiagnostic 区分未找到、多个匹配和唯一名称匹配。
  唯一名称匹配仍不是编译器声明、操作数边界、值流或原证明身份。
  原 automatic_l2_operand._authority 的批准条件没有改写。
- ledger 消费原 diagnostic.check_progress 已重新派生的检查点，按全部十项义务列出有限子目标、
  相关证据、尚缺消费者和下一步动作。完整证明消费者尚未连接，明确输出空列表；
  任何现有盘点、源条件排除或观察一致都不能在 ledger 中消解完整程序义务。
  ledger 的五阶段 inconclusive 是这些尚未闭合义务的保守展示，不是新批准算法。
- replan 只复用历史计划的配置，刷新 CLI/检查器身份；所有其他输入和工具快照及用例选择必须相同。
  建立全新目录并重新执行生产者，不接受旧检查点，也不修改旧收据的 verifier/hash。

本分支没有实现完整机器 ABI、内部对象访问证明、规范实例指令覆盖或完整 L1–L3。
没有授权修改原始宏。当前源条件排除的实例仍需保留结果，并选择原项目支持的真实可执行配置
或其他真实实例；不能修改阈值、删除失败样本或把入口命中当作规范实例执行。

## 1. 获取代码和运行回归

在原终端执行；工具目录须为新的目录。

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE194_PARENT:?}"
export PHASE195_TOOLING="$PREP_ROOT/tooling-phase195"
git -C "$REPO" fetch origin phase195-verification-profiling
git -C "$REPO" worktree add --detach "$PHASE195_TOOLING" origin/phase195-verification-profiling
export PHASE195_PARENT="$(mktemp -d "$PHASE194_PARENT/phase195-XXXXXX")"
export PYTHONPATH="$PHASE195_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE195_CLI="$PHASE195_TOOLING/experiment/automate_native_project.py"
git -C "$PHASE195_TOOLING" rev-parse HEAD
printf 'PHASE195_PARENT=%s\n' "$PHASE195_PARENT"
```

然后运行快速协议和已有相关回归；失败时先保留日志并停止真实长实验。

```bash
bash -e <<'REGRESSION'
: "${PHASE195_TOOLING:?}" "${PHASE195_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE195_TOOLING/pytools/tests/test_verification_session.py" \
 "$PHASE195_TOOLING/pytools/tests/test_verification_profile_cli.py" \
 "$PHASE195_TOOLING/pytools/tests/test_l2_binding_diagnostics.py" \
 "$PHASE195_TOOLING/pytools/tests/test_project_evidence_ledger.py" \
 "$PHASE195_TOOLING/pytools/tests/test_project_native_input.py" \
 "$PHASE195_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE195_TOOLING/pytools/tests/test_native_project_diagnostic.py" \
 "$PHASE195_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 "$PHASE195_TOOLING/pytools/tests/test_native_verifier_manifest.py" \
 --basetemp="$PHASE195_PARENT/pytest-focused" \
 > "$PHASE195_PARENT/focused.log" 2>&1
cat "$PHASE195_PARENT/focused.log"
REGRESSION
```

还应保留原框架入口和评估状态回归：

```bash
bash -e <<'ORIGINAL_REGRESSION'
: "${PHASE195_TOOLING:?}" "${PHASE195_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE195_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE195_TOOLING/pytools/tests/test_wide_integer_original.py" \
 "$PHASE195_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE195_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE195_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 --basetemp="$PHASE195_PARENT/pytest-original" \
 > "$PHASE195_PARENT/original-regression.log" 2>&1
cat "$PHASE195_PARENT/original-regression.log"
ORIGINAL_REGRESSION
```

真实工具测试有 skip 时提供完整 -rs 输出；协议 fixture 不是实际跨 ISA 证明。

## 2. 只重跑准备阶段，先测量复核成本

使用 Phase194 的原 diagnostic-plan.json 作为配置来源；无需手填 bundle、编译器和种子参数。
本轮绝不以新版代码 resume 旧版输出目录。

```bash
bash -e <<'PREPARE'
: "${PHASE194_PARENT:?}" "${PHASE195_PARENT:?}" "${PHASE195_CLI:?}"
status=0
python3 "$PHASE195_CLI" replan \
 --configuration "$PHASE194_PARENT/diagnostic/diagnostic-plan.json" \
 --output "$PHASE195_PARENT/diagnostic" \
 --stop-after preparation \
 --profile-output "$PHASE195_PARENT/preparation-profile.json" \
 > "$PHASE195_PARENT/preparation.log" 2>&1 || status=$?
printf 'preparation_status=%s\n' "$status"
cat "$PHASE195_PARENT/preparation.log"
test "$status" -eq 1
PREPARE
```

退出 1 是诊断未授予语义批准的约定。必须同时检查 JSON 为 paused、
completedStages 包含 preparation、currentAcquisitionFailures 为空；
单凭退出码 1 不能认定结果正确。退出 2、failed、检查异常先停止并提供日志。

此处要确认：
1. 新 functionBindingDiagnostic 实际报告零匹配、多个匹配还是唯一名称匹配；
2. 当前源条件分类及全部样本仍保留；
3. profile 中纯计算有无命中、是否因预算过小全部跳过；
4. 哪些函数 exclusiveSeconds 或 calls 高。
暂不声称性能提升；和 Phase194 比较必须区分同范围操作墙钟与嵌套阶段时间。

## 3. 在同一新计划下继续快速真实诊断

仅在第 1–2 步无异常后执行。新计划沿用旧计划的完整用例分母和明确选择；
当前选择 [0] 并不覆盖计划中的另一个用例。

```bash
bash -e <<'DIAGNOSE'
: "${PHASE195_PARENT:?}" "${PHASE195_CLI:?}"
status=0
python3 "$PHASE195_CLI" resume \
 --output "$PHASE195_PARENT/diagnostic" \
 --profile-output "$PHASE195_PARENT/resume-profile.json" \
 > "$PHASE195_PARENT/resume.log" 2>&1 || status=$?
printf 'resume_status=%s\n' "$status"
cat "$PHASE195_PARENT/resume.log"
test "$status" -eq 1
DIAGNOSE
```

预期生产链 complete、无当前采集失败。即使退出码/输出匹配，formalValidationPerformed、
semanticApproval 和 productionAcceptanceComplete 仍不能变成 true。

## 4. 空会话独立检查和证据清单

```bash
bash -e <<'CHECK'
: "${PHASE195_PARENT:?}" "${PHASE195_CLI:?}"
python3 "$PHASE195_CLI" check \
 --input "$PHASE195_PARENT/diagnostic/progress.json" \
 --verification-cache-mib 0 \
 --profile-output "$PHASE195_PARENT/check-no-cache-profile.json" \
 > "$PHASE195_PARENT/check-no-cache.log" 2>&1
python3 "$PHASE195_CLI" ledger \
 --input "$PHASE195_PARENT/diagnostic/progress.json" \
 --profile-output "$PHASE195_PARENT/ledger-profile.json" \
 > "$PHASE195_PARENT/evidence-ledger.json"
CHECK
```

check 成功只表示收据一致且可重派生。ledger 应列出全部十项未闭合义务、未选用例、
真实观察、源条件分类及 L2 精确诊断；它不报告 L0/L1 已通过。

若需要缓存开/关的同范围对比，可在同一新版已完成输出上额外执行一次
check --verification-cache-mib 256，profile 使用新文件名。两次结论应一致。
墙钟比较受文件系统热缓存、负载和 Python 分配器影响；至少确认调用范围相同，
再按需要复测，不能把一次差值直接写成确定加速比。

## 5. 何时继续正式实验

formal 命令仍调用原 campaign / run_evaluation，保留完整矩阵及原计划用例：

```bash
python3 "$PHASE195_CLI" formal --output "$PHASE195_PARENT/diagnostic" \
 --profile-output "$PHASE195_PARENT/formal-profile.json" \
 > "$PHASE195_PARENT/formal.log" 2>&1
```

这一步不是当前缺少生产能力的修复手段。先根据 ledger 和 L2 诊断补齐实际义务，
或明确只做正式矩阵基线测量，再决定是否支付其成本。源排除实例不应被称作规范指令覆盖。
原始宏回填、完整 ABI、对象访问及 L2/L3 授权没有证据时必须继续未完成。

## 请提供的结果

优先提供 focused.log、original-regression.log、preparation.log、
preparation-profile.json。随后提供 resume.log、resume-profile.json、
check-no-cache.log、check-no-cache-profile.json、evidence-ledger.json。
无需重新上传 466 份无关构建上下文；若新诊断显示具体缺项，再按身份提取该项。

# Phase192：在原评估链中采集当前双端机器事实

## 修订目的与边界

Phase191 已推送，不存在尚未保存的代码。本轮是在该提交上继续补足机器事实生产：
原 `program_machine_evidence.py` 的受限 AMD64 叶函数引理保留；新增生产器采用同一
pypcode/SLEIGH 体系，对 RV64GC 和 AMD64 的有大小函数符号逐条解码，跨越分支与调用，
记录每条指令的精确字节、p-code、控制操作、LOAD/STORE 和区域内重定位。

函数来自当前原候选的精确编辑绑定及其编译器 AST 所属函数。链接名必须由编译器
显式给出 `mangledName`，不使用函数名模式、反汇编文本或源码行猜测；缺失时保留缺口。
然后检查当前对象与当前重链接动态库的符号元数据，不采用旧候选的产物。

本轮盘点对应 L1 使用的这一对工程构建，不代表全部 18 格矩阵均取得机器事实；
不同优化或编译器配置的覆盖与 ABI 证据不能相互套用。

逐条解码采用最多 16 字节的输入窗口，避免反复复制整个函数剩余区域；仍检查
AMD64 最长 15 字节、当前 RV64GC 最长 4 字节的指令边界。
每个函数限制 64 KiB / 100000 个 p-code 操作。解码失败、预算不足、缺失符号和
不支持的区域明确记录；未解码后缀不会被算作完整。

**线性字节解码完整不等于 CFG、实际可达或执行覆盖完整。** 盘点可能包含不可达代码和
填充字节。SLEIGH 模型给出的内存操作不是完整对象模型；指针来源、生命周期、边界、
别名及调用效果仍需证明。编译器链接名与符号元数据对应，也不等于宏实例到规范指令区域
的证明。完整机器 ABI、内部对象合法性、规范实例执行覆盖依旧不被宣布通过。

## 原框架接入

仍通过 `automate_native_project.py` 自动调用原 Pipeline、回填、独立候选重跑、
原 `evaluation.run_evaluation`、原 18 格 L0 和原过程比较器，没有另一条翻译路线。

当请求具有 Phase191 的实例适用性收据且原评估执行到 L1 时，自动生成
`machine-inventory.json`。它绑定：

- 当前冻结工程、原候选实例、编译器 AST 所属函数；
- 双端真实 build 收据、对象、动态库和测试可执行文件；
- pypcode 扩展、适配器、SLEIGH 和处理器规范文件身份。

原结果检查路径重新解码和派生，核查收据属于本请求及本次实际程序。修改事实并重新
计算 JSON 哈希不能通过检查。机器事实收据随原评估的保留文件一并存档；L1 detail 和
逐尝试摘要通过 `machineInventory` 给出实际路径。不会仅按文件名或目录存在复用。

L1 的 ABI 等义务保持原样。L1 inconclusive 时原调度器仍不会绕过它宣布 L2/L3 完成。
本轮产生后续分析所需事实，并未闭合全部程序级证明。自然加载身份、三端编译关系、
输入对应、函数内部对象和调用效果、规范实例区域与运行事件仍需继续补足。

## 验证步骤

不要在旧 Phase191 工作树上覆盖源码，也不要用新验证器恢复旧进度。继续复用底层
原始 bundle 和构建记录，在新输出目录自动重跑。变量在当前终端导出。

### 1. 更新工作树

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE192_TOOLING="$PREP_ROOT/tooling-phase192"
export PHASE192_PARENT="$(mktemp -d "$PHASE188_ROOT/phase192-XXXXXX")"
export PYTHONPATH="$PHASE192_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE192_CLI="$PHASE192_TOOLING/experiment/automate_native_project.py"
bash -e <<'SETUP'
: "${REPO:?}" "${PHASE192_TOOLING:?}"
git -C "$REPO" fetch origin phase192-original-machine-inventory
git -C "$REPO" worktree add --detach "$PHASE192_TOOLING" origin/phase192-original-machine-inventory
git -C "$PHASE192_TOOLING" rev-parse HEAD
SETUP
```

### 2. 定向回归

```bash
bash <<'TEST'
: "${PHASE192_TOOLING:?}" "${PHASE192_PARENT:?}"
python3 -m pytest -q -rs \
 "$PHASE192_TOOLING/pytools/tests/test_program_machine_inventory.py" \
 "$PHASE192_TOOLING/pytools/tests/test_program_proof_components.py" \
 "$PHASE192_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE192_TOOLING/pytools/tests/test_native_project_campaign.py" \
 "$PHASE192_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 "$PHASE192_TOOLING/pytools/tests/test_original_source_applicability.py" \
 "$PHASE192_TOOLING/pytools/tests/test_project_obligation_assessment.py" \
 "$PHASE192_TOOLING/pytools/tests/test_evaluation_state_separation.py" \
 "$PHASE192_TOOLING/pytools/tests/test_partial_program_evaluation.py" \
 --basetemp="$PHASE192_PARENT/pytest" > "$PHASE192_PARENT/focused.log" 2>&1
status=$?
printf 'focused_status=%s\n' "$status"
cat "$PHASE192_PARENT/focused.log"
exit "$status"
TEST
```

本地 RV 测试使用精确 RV 指令字节及合成 ELF 容器，未执行真实 RISC-V 程序；
原编译器入口和部分工程绑定是明确模拟的测试边界。它们不能替代下述真实 GMP 实验。

### 3. 自动执行真实实验

```bash
bash <<'RUN'
: "${PHASE192_CLI:?}" "${PHASE192_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE192_CLI" run \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 10 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC --timeout-seconds 600 \
 --output "$PHASE192_PARENT/campaign" > "$PHASE192_PARENT/campaign.log" 2>&1
status=$?
printf 'campaign_status=%s\n' "$status"
cat "$PHASE192_PARENT/campaign.log"
exit "$status"
RUN
```

仍可增加 `--stop-after applicability` 先暂停，然后以 `resume --output` 自动继续。
不需要手工创建 EvaluationRequest、编译/链接脚本或机器事实文件。
参数 10 保持 GMP 官方的尺寸覆盖停止规则，不是严格固定十次输入；主体至少 11 次，
尺寸覆盖不足可继续。18 格 L0、原独立检查及样本分母不变。需要默认 1000 配置时，
在新的输出目录显式传入 1000，并分开记录结果。

CLI 返回 0 为原请求 verified，1 为正常未 verified 的结果（或主动暂停），2 为异常。
L0 没通过就不会越过它运行 L1，也不会生成 L1 机器收据。

### 4. 检查与导出信息

```bash
python3 "$PHASE192_CLI" check --input "$PHASE192_PARENT/campaign/progress.json"
python3 "$PHASE192_CLI" timings --input "$PHASE192_PARENT/campaign/progress.json" \
 > "$PHASE192_PARENT/timings.json"
```

原计时增加 L1 `machineInventorySeconds`，包含生产及立即独立重派生的开销。
阶段/层级/命令计时有嵌套，不应把全部行直接相加。机器事实还会在结果检查时重新派生，
不能以这个字段代替整次实验总耗时。

请提供 focused.log、campaign.log、campaign/progress.json、timings.json。
若到达 evaluation，再提供 resultPaths.evaluation 指向的 result.json、同目录
`evaluation-result.json`，以及逐尝试 `machineInventory.path` 指向的完整收据。
只提供已经生成的文件。收据中的每个函数可区分：链接名不足、符号对应不足、部分解码
或字节盘点完整；这些都不能直接升级为完整 ABI 或实例覆盖。

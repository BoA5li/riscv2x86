# Phase 87：SYSTEM源模型与运行时合同闭合

基线：phase86-system-instruction-authority，f2b134e34e90eafc26b89dcdd1b45273bf1b00f7。
新分支：phase87-system-source-contract-closure。

## 修订及边界

准备工具原先在基本特权状态上生成合同身份，生产流水线还会加入CSR operand binding、状态数据流和CSR源模型，因此Phase 6C无法匹配合同。
两端现在复用 privileged_source_state.complete_privileged_source_state；原有CSR authority解析和执行权限检查仍由各自入口完成。
本轮没有更改身份算法或注册表schema，也没有忽略任何源状态字段。

prepare另存source-binding.json供审查（不是许可）；实际消费者仍独立重建模型并严格比较身份。
注册键缺失与源身份不匹配现在分别记录resolutionReason，包含实际请求键、合同ID及预期／实际源身份。
Phase 6C details经过translationPlanAttempts保留到报告；驱动器批准失败时保存failureDiagnostics。

支持域仍为显式受控、单hart M-mode bare环境：ECALL为已注册handler返回关系；WFI为MTIP预先pending的有限关系。
不声明native Linux用户态ECALL、一般未来中断等待、无界活性、任意函数或L3等价。
旧合同、批准和provider必须重新生成；后端及库身份未变化时可复用已准备的后端。

## 1. 更新、构建和定向回归

以下在已激活的.venv-l2中执行。分块执行；状态非0先检查日志，不继续依赖步骤。
不使用set -e、exit、reset或清理旧实验目录。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase87-system-source-contract-closure
git switch --track origin/phase87-system-source-contract-closure
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PHASE87_ROOT="$(mktemp -d "$REPO/experiment/results/phase87-XXXXXX")"
printf '%s\n' "$PHASE87_ROOT"
cmake --build build -j2 > "$PHASE87_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE87_ROOT/build.log"
```

若本地已有该分支，使用git switch phase87-system-source-contract-closure；不要重复--track。

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_privileged_source_completion.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_system_preparation.py \
  pytools/tests/test_system_deployment.py \
  pytools/tests/test_system_instruction_ingress.py \
  --junitxml="$PHASE87_ROOT/focused.xml" \
  > "$PHASE87_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 35 "$PHASE87_ROOT/focused.log"
```

其中包含真实p-code、合同JSON加载、pipeline.run的实际模型构造、Phase 6D与renderer、旧合同拒绝及独立进程身份稳定性。
组件测试的assembler输入／源传输fixture不构成真实QEMU生产验收。

## 2. 原始ECALL和WFI真实生产链

复用此前已成功准备的受控SYSTEM backend；validate_backend会重新核对其身份。
以下为本次用户提供的实际路径。

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$REPO/experiment/results/phase86-rQLWHm/controlled-system/backend.json"
export RV2X86_SYSTEM_CLANG="$CLANG10"
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --output "$PHASE87_ROOT/system" \
  > "$PHASE87_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 50 "$PHASE87_ROOT/system-driver.log"
python3 -m json.tool "$PHASE87_ROOT/system/run-status.json"
```

输出目录必须此前不存在。失败重跑时换新的输出子目录，不覆盖旧结果。
必须同时满足：状态0、completedRoutes包含ecall和wfi、productionAcceptanceComplete=true、每条路线L0/L1/L2 verified、中央provider审计通过。
bootstrap缺少合同的拒绝是预期准备步骤；approval必须获批；configured及audit必须成功。

## 3. 合法重命名生产验收

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE87_ROOT/production.xml" \
  > "$PHASE87_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 60 "$PHASE87_ROOT/production.log"
```

要求2 passed、0 skipped、状态0。工具未选择或缺失不能记为生产成功。
原始和重命名输入均成功后，才进行组合验收。

## 4. 组合验收

提供同一有效024/029准备运行的architecture、CSR、sync目录及已审计provider目录；不要使用裸基线替代配置后的组合运行。
下面沿用此前成功目录；若后来在Phase85重新准备过，替换COMBINED_2429为最新成功目录。

```bash
export COMBINED_2429="$REPO/experiment/results/phase84-LzQiP3/combined"
ls -ld "$COMBINED_2429/contracts/architecture" "$COMBINED_2429/contracts/csr" \
  "$COMBINED_2429/contracts/sync" "$COMBINED_2429/contracts/providers"
python3 experiment/run_controlled_system_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --suite "$REPO/experiment/generated-suite" \
  --existing-provider-directory "$COMBINED_2429/contracts/providers" \
  --csr-architecture-directory "$COMBINED_2429/contracts/architecture" \
  --csr-environment-contract-directory "$COMBINED_2429/contracts/csr" \
  --instruction-stream-sync-directory "$COMBINED_2429/contracts/sync" \
  --output "$PHASE87_ROOT/combined" \
  > "$PHASE87_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE87_ROOT/combined-driver.log"
python3 -m json.tool "$PHASE87_ROOT/combined/run-status.json"
python3 -m json.tool "$PHASE87_ROOT/combined/suite-preservation.json"
```

SYSTEM合同和provider由新驱动器重新生成。旧SYSTEM配置因observer源码身份变化不可直接复用。

要求每条受支持路线有独立真实验收、suite-preservation没有原有正确案例退化、中央审计通过。
固定32项测试集的目标为30 verified和023/026两项非法输入拒绝；计数只是交叉检查，不作为语义批准条件。
016/022、024、029及原生案例各自保留实际环境归属；不可宣称全部在native QEMU用户环境严格等价。

## 5. 最终选定无跳过回归

保留第2节SYSTEM环境变量，同时显式选择既有024和029生产环境；以下路径沿用此前成功实验。
若环境、CPU前提或文件身份变化，须按其准备流程重新生成。

```bash
export PREVIOUS_ROOT="$REPO/experiment/results/phase83-production-ToHPRs"
export RV2X86_LOCAL_SYNC_DECLARATION="$PREVIOUS_ROOT/sync-selection.json"
export RV2X86_QEMU_SOURCE="$REPO/qemu"
export RV2X86_QEMU_BUILD="$REPO/qemu/build"
export RV2X86_NATIVE_RUNNER_JSON='["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
export RV2X86_CONTROLLED_QEMU_MANIFEST="$PREVIOUS_ROOT/controlled-qemu/backend.json"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON="$(python3 -c 'import json,os; print(json.dumps([os.path.join(os.environ["PREVIOUS_ROOT"],"controlled-qemu/build/qemu-riscv64"),"-L","/usr/riscv64-linux-gnu"]))')"
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE87_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE87_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 30 "$PHASE87_ROOT/regression-driver.log"
tail -n 20 "$PHASE87_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE87_ROOT/regression-final/run-status.json"
```

要求零失败、零错误、零跳过、blockers为空。此命令未传--suite，所以不会重新执行32项组合测试；第4节组合验收必须单独保留。
本回归范围是verify_route_contracts.py列出的测试集合，不是全仓库所有历史测试通过的声明。

## 日志核查

优先提供system/run-status.json和system-driver.log。
若批准失败，failureDiagnostics含reportPath、translationPlanAttempts、身份匹配详情及授权决策，无需再手写大型提取脚本。
继续查看system/system-N-approval.log、system-N-configured.log、system-N-provider-audit.log（N按--source顺序从0开始）。
contracts/<源码名>/source-binding.json为准备模型审查记录；不是批准。
实际批准在对应translated_report.json，实际L0/L1/L2和环境归属在configured/batch-evaluation.json及案例报告。
原始执行stdout/stderr、命令、产物摘要和本次execution nonce在层级证据内。

## 本次可验证范围

开发环境没有真实Clang frontend、llvm-mc、RISC-V GCC或QEMU-system。因此本次不能声明实际QEMU源端、完整组合或无跳过生产回归通过。
推送前验证结果另记录在修订提交说明／交付说明中；以上宿主机生产命令是最终验收要求。

## 开发环境验证记录

- 选定route-contract回归：1153 passed，43 skipped；新增10项测试。
- 对比Phase86的1186项既有测试：没有任何结果变化。
- 43项跳过均为未选择受控SYSTEM后端或缺少真实Clang／llvm-mc／交叉GCC／QEMU等工具，不能算生产验收成功。
- 更广历史语义集合：412 passed，10 failed，2 skipped；与Phase86逐项比较无变化，10项历史失败仍未解决，不声明全仓库全绿。
- 定向pipeline/contract测试：实际流水线构造可以取得Phase 6D批准并产生候选；verify_enabled=False时继续withheld，未冒充外部构建验证通过。
- 两种指令的完整准备模型身份在三个不同PYTHONHASHSEED的独立进程中稳定；本轮保留现有身份算法。

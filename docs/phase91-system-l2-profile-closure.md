# Phase 91：ECALL 的 L2 profile、需求与 provider 闭合

基线：phase90-system-reproducible-builds，06dd97bbdf6d2bba08603d68b1627a60401a4a0e。
新分支：phase91-system-l2-profile-closure。

## 修改与边界

用户生产ECALL已经L0/L1 verified，但L2在requirement_classification返回semantic-profile.incomplete。
根因是profile_from_source_model识别CSR／返回／中断等效果，却未识别完整的显式environment_call；
结果privileged shape本身complete，patternKind却为unknown。WFI的interrupt effect已被覆盖，因此没有同一问题。

现在仅对真实SourcePrivilegedSemanticModel、已闭合且一致的semantic presence／state、
由现有typed route classifier识别的精确单一ECALL效果，归入privileged_write。
该类别承载异常入口保存状态的转换义务，不表示任意潜在trap都属于特权写。
普通CSR读取可能trap仍是privileged_read；缺失handler／不完整或复合trap事实／未经类型验证的记录不取得本分支分类。
不消费案例编号、路径、函数名、helper名或汇编字符串授予资格，也不从已有批准强制补complete。

profile完整性、批准、compiler-bound authority、全部required dimensions、provider适用性及中央closer检查均保留。
不完整profile仍保留原拒绝码，并增加unknown pattern／privileged shape／internal state／escape的适用诊断。
WFI生产测试按实际四层报告严格检查L0/L1/L2 verified、L3 not_run，不删除L3记录或声称L3等价。

扩展现有真实p-code/contract/pipeline组件测试，直接消费pipeline输出的profile，再经过真实classifier及provider resolver；
增加不完整、复合、其他trap、无authority／无匹配provider的拒绝。组件中的外部编译器事实和源执行传输仍明确为fixture，不冒充QEMU生产。

本轮未修改构建recipe、启动／内核／runtime及SYSTEM observer源码；此前有效Phase90 backend可直接复用。
无需例行重建QEMU或重复backend升级。搜索环境、工具或产物变化时仍须重新核对／显式预检。
所有新生产运行使用新目录，重新生成批准、profile、需求和provider绑定；不能复用旧报告。
支持域仍是显式单hart M-mode bare的handler返回／MTIP预先pending，不扩展native Linux用户态或L3。

## 1. 更新、固定环境与构建

已激活.venv-l2，优先沿用Phase90成功运行的终端和工具搜索环境。
每块返回非0先检查对应日志，不继续依赖步骤。不使用set -e或shell exit。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase91-system-l2-profile-closure
git switch --track origin/phase91-system-l2-profile-closure
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$REPO/experiment/results/phase90-M3h0OX/controlled-system/backend.json"
export PHASE91_ROOT="$(mktemp -d "$REPO/experiment/results/phase91-XXXXXX")"
printf 'PHASE91_ROOT=%s\n' "$PHASE91_ROOT"
cmake --build build -j2 > "$PHASE91_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 25 "$PHASE91_ROOT/build.log"
```

本地已有该分支时使用git switch phase91-system-l2-profile-closure。
不要在复用backend前再次无条件追加Clang PATH前缀，profile绑定实际搜索环境。

## 2. 定向测试并核对可复用backend

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_l2_semantic_profile.py \
  pytools/tests/test_l2_requirement_driven_registry.py \
  pytools/tests/test_l2_materialization_closure.py \
  pytools/tests/test_system_instruction_ingress.py \
  pytools/tests/test_privileged_source_completion.py \
  --junitxml="$PHASE91_ROOT/focused.xml" \
  > "$PHASE91_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 40 "$PHASE91_ROOT/focused.log"
```

```bash
python3 -c 'import os; from riscv2x86_py.controlled_system_backend import validate_backend; b=validate_backend(os.environ["RV2X86_CONTROLLED_SYSTEM_BACKEND"]); print("backend validated:",b["backendIdentity"]); print("profile:",b["buildProfile"]["schemaVersion"],b["buildProfile"]["policy"])' \
  > "$PHASE91_ROOT/backend-validation.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
cat "$PHASE91_ROOT/backend-validation.log"
```

两者状态均须0。若profile提示搜索环境变化，恢复其已记录环境或按Phase90指南在新环境显式upgrade-backend；
不修改profile字段以消除拒绝。新的终端可以先核对manifest的buildProfile.searchEnvironment；不要根据测试结果随意换编译器。

## 3. 原始输入完整生产验收

```bash
export RV2X86_SYSTEM_CLANG="$CLANG10"
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --output "$PHASE91_ROOT/system" \
  > "$PHASE91_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 50 "$PHASE91_ROOT/system-driver.log"
python3 -m json.tool "$PHASE91_ROOT/system/run-status.json"
```

要求状态0、completedRoutes包含ecall和wfi、productionAcceptanceComplete=true、两条路线L0/L1/L2均verified且中央审计通过。
未配置bootstrap拒绝是预期；不能把approval批处理退出码1独立解释为证明失败，驱动器还会核查批准内容。
配置后程序仍使用profile中的原命令策略并重新检查实际产物。原始输入和profile内的构建示例不是同一次验证。

## 4. 合法重命名生产验收

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE91_ROOT/production.xml" \
  > "$PHASE91_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 60 "$PHASE91_ROOT/production.log"
```

要求2 passed、0 skipped。若输入工具不具备条件，不得计为生产成功。

## 5. 组合与最终无跳过回归

以上步骤全部通过后，选择此前已成功且身份仍有效的024/029准备目录。若使用了更新的成功目录，替换COMBINED_2429。

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
  --output "$PHASE91_ROOT/combined" \
  > "$PHASE91_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE91_ROOT/combined-driver.log"
python3 -m json.tool "$PHASE91_ROOT/combined/run-status.json"
python3 -m json.tool "$PHASE91_ROOT/combined/suite-preservation.json"
```

SYSTEM合同和provider由本次驱动器重新生成，不复用旧批准或执行报告；有效Phase90 backend继续复用。

要求每条受支持路线有独立真实验收、suite-preservation没有原有正确案例退化、中央审计通过。
固定32项测试集的目标为30 verified和023/026两项非法输入拒绝；计数只是交叉检查，不作为语义批准条件。
016/022、024、029及原生案例各自保留实际环境归属；不可宣称全部在native QEMU用户环境严格等价。

随后显式选择此前成功的024/029环境，保持SYSTEM backend及工具搜索环境不变：

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
  --output "$PHASE91_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE91_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE91_ROOT/regression-driver.log"
tail -n 20 "$PHASE91_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE91_ROOT/regression-final/run-status.json"
```

要求零失败、零错误、零跳过、blockers为空。未传--suite，此命令不重复组合实验。

## 日志核查与验收边界

先看backend-validation.log及所选backend引用的build-profile/profile.json，再看system/run-status.json的currentStage、blockers和failureDiagnostics。
具体程序构建有*.build.log、*.build.log.json、*.build.log.failure.json和*.build.json。
每个产物有独立的<产物名>.build目录，保留wrapper、对象、各阶段日志及命令。记录中的command是最终链接命令，完整流程必须查看steps和cwd。
L0的system-l0-<运行身份>目录保留六项独立重建；不一致时rebuild-mismatch目录保存original.elf、rebuilt.elf、comparison.json。
驱动器failureDiagnostics.rebuildMismatches直接引用这些记录，不能只检查buildFailures是否为空。
通过预检或通过组件测试，不代表实际QEMU执行、逐维证据和中央closer通过。
开发环境没有真实交叉GCC／QEMU-system；真实宿主机构建和生产验收仍是交付后的必要验证，不预先声明完成。

## 开发环境验证

选定回归分两组执行：64 passed，以及1163 passed、43 skipped，共1227 passed、43 skipped、零失败。
与Phase90的1268项既有测试逐项比较，结果全部不变；新增2项负测通过。43项跳过分别为2项未选择真实M-mode backend、40项缺少真实生产工具链、1项缺少源ISA工具。
这些结果不等于无跳过生产验收。实际ECALL L2执行、中央审计、原始双路线、组合和无跳过回归仍须按上面宿主机步骤完成。

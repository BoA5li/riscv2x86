# Phase 90：SYSTEM 可重现构建与 L0 重建证据

基线：phase89-system-linker-profile，b01894528dd2b18adec0408ec33fae8d10f1183f。
新分支：phase90-system-reproducible-builds。

## 解决的问题和边界

实际RV64 ELF的STT_FILE含/tmp/ccj8xQ2p.o。一次GCC调用编译多个输入时，
没有.file声明的启动汇编可能将临时对象名带入ELF。构建成功并不保证跨目录全文件可重现。
原生产L0的整文件摘要比较因此被触发，L1/L2没有执行。

本轮保留已审查的启动／内核／runtime及其实现身份，不修改指令语义或删除摘要比较：

1. 源端分别编译wrapper.o、kernel.o、boot.o，再从固定工作目录使用相对对象名链接。
2. 目标端同样分离编译和链接。每个输出使用独立的<产物名>.build工作目录，不覆盖另一侧wrapper。
3. 记录所有阶段的command、cwd、输入／wrapper摘要、对象摘要、退出码、stdout/stderr和最终ELF。
4. profile每个矩阵项在另一个目录独立重复构建，完整文件摘要必须相同。12项逻辑矩阵对应24次构建。
5. L0独立重建保留在原始产物旁的system-l0-<身份>目录；不一致时保留两份ELF、摘要、首个差异位置、节／LOAD诊断和构建记录。
6. 无论差异位于指令、符号表或其他区域，均保持拒绝；不strip、不忽略节、不归一化产物。

program build记录升级为riscv2x86.system-program-build.v2，profile升级为riscv2x86.system-build-profile.v2，
policy升级为rv64i-lp64-bare-no-relax.v3；backend仍使用v2封装。
原有三种relax策略和ELF约束保留。profile消费复核两次构建的每个阶段、对象、wrapper和最终产物。
旧profile必须重新预检；通过upgrade-backend可复用已验证QEMU/runtime，无需重建QEMU。
下面使用此次已成功准备的phase89-XWQqfJ backend；原phase86 backend也可用于显式升级。
新backend、recipe和observer身份要求重新准备SYSTEM合同、批准和provider，不能复用旧SYSTEM发布记录。

支持域仍为显式受控单hart M-mode ECALL handler返回和MTIP预先pending的WFI；
不声明native Linux用户态、一般未来中断等待、任意程序或L3等价。
本轮修复L0构建阻塞，不预先保证尚未执行到的L1/L2没有其他问题。

## 1. 更新和定向回归

在已激活的.venv-l2中逐块执行。状态非0先检查日志，不继续依赖步骤；不使用set -e或exit。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase90-system-reproducible-builds
git switch --track origin/phase90-system-reproducible-builds
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PHASE90_ROOT="$(mktemp -d "$REPO/experiment/results/phase90-XXXXXX")"
printf '%s\n' "$PHASE90_ROOT"
cmake --build build -j2 > "$PHASE90_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 25 "$PHASE90_ROOT/build.log"
```

若本地已有该分支，使用git switch phase90-system-reproducible-builds。

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_system_build_profile.py \
  pytools/tests/test_system_build_reproducibility.py \
  pytools/tests/test_route_contract_regression_runner.py \
  pytools/tests/test_privileged_source_completion.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_system_preparation.py \
  pytools/tests/test_system_deployment.py \
  pytools/tests/test_system_instruction_ingress.py \
  --junitxml="$PHASE90_ROOT/focused.xml" \
  > "$PHASE90_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 40 "$PHASE90_ROOT/focused.log"
```

组件测试中source的合成RV64 ELF明确不是源端真实构建或QEMU执行。真实目标GCC矩阵、策略拒绝和身份mutation测试也不能替代第2—4节。

## 2. 复用旧QEMU，显式升级构建profile

必须在第1节设置好PATH后执行；后续实验保留同一工具搜索环境。

```bash
python3 -m riscv2x86_py.controlled_system_backend upgrade-backend \
  --backend "$REPO/experiment/results/phase89-XWQqfJ/controlled-system/backend.json" \
  --output "$PHASE90_ROOT/controlled-system" \
  > "$PHASE90_ROOT/backend-upgrade.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 50 "$PHASE90_ROOT/backend-upgrade.log"
```

成功后检查新profile：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['PHASE90_ROOT'])/'controlled-system/backend.json'
b=json.loads(p.read_text()); profile=b['buildProfile']
print('backendSchema',b['schemaVersion'])
print('backendIdentity',b['backendIdentity'])
print('profileSchema',profile['schemaVersion'])
print('policy',profile['policy'])
print('relaxMode',profile['relaxMode'])
print('profileIdentity',profile['profileIdentity'])
print('buildCount',len(profile['records']))
for r in profile['records']:
    print(r['side'],r['operation'],r['optimization'],r['returnCode'],
          r['reproduction']['returnCode'],r['programDigest']==r['reproduction']['programDigest'])
PY
```

要求backend_status=0、backend v2、profile v2、policy v3；12条主记录及12条独立重复记录均returnCode=0，逐对摘要相同。semanticApproval=false是正常的：构建能力不是翻译证明。
三种候选按顺序独立探测；前两种拒绝不是最终失败。当前GCC 7.5／Binutils 2.30预计选择linker-norelax，但只有完整12对（24次构建）通过才可确认；不能按版本强制选择。
若三种都失败，保留backend-upgrade.log和controlled-system/build-profile/probe-attempts.json，及build-profile-status.json，以及对应*.build.log和*.build.log.json；不要手工删参数或修改manifest。
重跑升级使用新的输出目录，不覆盖失败目录。升级不会修改旧backend或重建QEMU。

## 3. 原始输入完整生产验收

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$PHASE90_ROOT/controlled-system/backend.json"
export RV2X86_SYSTEM_CLANG="$CLANG10"
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --output "$PHASE90_ROOT/system" \
  > "$PHASE90_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 50 "$PHASE90_ROOT/system-driver.log"
python3 -m json.tool "$PHASE90_ROOT/system/run-status.json"
```

要求状态0、completedRoutes包含ecall和wfi、productionAcceptanceComplete=true、两条路线L0/L1/L2均verified且中央审计通过。
未配置bootstrap拒绝是预期；不能把approval批处理退出码1独立解释为证明失败，驱动器还会核查批准内容。
配置后程序仍使用profile中的原命令策略并重新检查实际产物。原始输入和profile内的构建示例不是同一次验证。

## 4. 合法重命名生产验收

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE90_ROOT/production.xml" \
  > "$PHASE90_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 60 "$PHASE90_ROOT/production.log"
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
  --output "$PHASE90_ROOT/combined" \
  > "$PHASE90_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE90_ROOT/combined-driver.log"
python3 -m json.tool "$PHASE90_ROOT/combined/run-status.json"
python3 -m json.tool "$PHASE90_ROOT/combined/suite-preservation.json"
```

SYSTEM合同和provider由新驱动器重新生成。旧SYSTEM配置因observer源码身份变化不可直接复用。

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
  --output "$PHASE90_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE90_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE90_ROOT/regression-driver.log"
tail -n 20 "$PHASE90_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE90_ROOT/regression-final/run-status.json"
```

要求零失败、零错误、零跳过、blockers为空。未传--suite，此命令不重复组合实验。

## 日志核查与验收边界

先看backend-upgrade.log及build-profile/profile.json，然后system/run-status.json的currentStage、blockers和failureDiagnostics。
具体程序构建有*.build.log、*.build.log.json、*.build.log.failure.json和*.build.json。
每个产物有独立的<产物名>.build目录，保留wrapper、对象、各阶段日志及命令。记录中的command是最终链接命令，完整流程必须查看steps和cwd。
L0的system-l0-<运行身份>目录保留六项独立重建；不一致时rebuild-mismatch目录保存original.elf、rebuilt.elf、comparison.json。
驱动器failureDiagnostics.rebuildMismatches直接引用这些记录，不能只检查buildFailures是否为空。
通过预检或通过组件测试，不代表实际QEMU执行、逐维证据和中央closer通过。
开发环境没有真实交叉GCC／QEMU-system；真实宿主机构建和生产验收仍是交付后的必要验证，不预先声明完成。

## 开发环境结果

选定回归分组执行：1225 passed、43 skipped、0 failed。
其中构建策略57项、可重现性与L0证据12项、controlled-system及回归驱动器42项通过；其余1114 passed、43 skipped。
与Phase89逐项比较，构建策略测试之外1199项既有测试结果无变化。
真实native GCC验证不同目录／输出名全文件一致、无.file汇编的相对对象身份；
实际L0调用组件测试验证源／目标任意完整字节差异仍拒绝并保留证据。
源RV64构建使用明确标记的协议fixture；没有实际交叉GCC、Clang／llvm-mc或QEMU可用于本机生产验收。
43项跳过来自生产工具或显式后端缺失，不计为生产成功。未重跑全仓库历史集合，不声明全仓库全绿。
实际交叉构建、QEMU源执行、中央审计、组合和无跳过选定回归必须在宿主机完成。

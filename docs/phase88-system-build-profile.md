# Phase 88：受控SYSTEM完整构建能力与旧GCC适配

基线：phase87-system-source-contract-closure，80ab25855b0acacdec0cadf2bac7e571c22a0d21。
新分支：phase88-system-build-profile。

## 变更和支持范围

旧准备只检查CSR小片段，生产硬编码-mno-relax。用户的GCC 7.5拒绝该驱动参数。
新增system_build_profile：准备预检、实际构建和L0矩阵复用同一命令生成器。
允许的配置仅有：

- driver-norelax：-mno-relax和-Wl,--no-relax；
- assembler-norelax：-Wa,-mno-relax和-Wl,--no-relax。

按真实完整构建能力选择；不按GCC版本或测试案例名称选择，不存在省略relaxation控制的候选。
官方参数传递依据：https://gcc.gnu.org/onlinedocs/gcc/Assembler-Options.html 。
GNU assembler选项：https://sourceware.org/binutils/docs-2.31/as/RISC_002dV_002dOptions.html 。
GNU ld选项：https://sourceware.org/binutils/docs-2.30/ld/Options.html 。
这些文档不是本机工具能力证明；本机完整编译、汇编、链接与产物检查才决定配置是否可用。

预检包含ECALL/WFI × O0/O2/O3 × source/target共12个构建。源程序必须为ELF64小端RV64、LP64 soft-float、无RVC标志、静态可执行，入口0x80000000且位于可执行LOAD段；物理／虚拟装载地址符合bare RAM范围，无动态加载器、无未定义符号；检查BSS／栈布局和gp的AUIPC+ADDI实际地址关系。
目标程序必须为实际可执行的ELF64小端x86-64产物。生产输入仍须独立构建和实际运行，预检不是翻译或语义批准。

backend v2绑定构建profile、实际工具（driver/cc1/assembler/linker/collect2）、specs和可解析的工具链输入、搜索环境及构建recipe身份。
消费者复核保留的预检源码、wrapper、命令、产物摘要及ELF检查，不将一个profile哈希视为实际构建成功。
保留整个profile目录；不能只拷贝backend.json。工具、搜索环境或recipe变化后需显式重新预检。
旧v1仍可读取以验证既有QEMU/runtime，不能用于源SYSTEM生产构建；通过upgrade-backend生成新的v2。
旧合同和SYSTEM provider要重新准备。QEMU和已核对的runtime可复用，不需要重建QEMU。

构建错误保留实际命令、退出码、stdout/stderr、超时及部分输出。配置后失败的驱动状态会关联具体build failure文件及案例报告。
当前支持域仍为单hart M-mode bare的handler返回／已pending MTIP；不扩大为native Linux用户态、一般中断等待或L3。

## 1. 更新和定向回归

在已激活的.venv-l2中逐块执行。状态非0先检查日志，不继续依赖步骤；不使用set -e或exit。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase88-system-build-profile
git switch --track origin/phase88-system-build-profile
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PHASE88_ROOT="$(mktemp -d "$REPO/experiment/results/phase88-XXXXXX")"
printf '%s\n' "$PHASE88_ROOT"
cmake --build build -j2 > "$PHASE88_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 25 "$PHASE88_ROOT/build.log"
```

若本地已有该分支，使用git switch phase88-system-build-profile。

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_system_build_profile.py \
  pytools/tests/test_privileged_source_completion.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_system_preparation.py \
  pytools/tests/test_system_deployment.py \
  pytools/tests/test_system_instruction_ingress.py \
  --junitxml="$PHASE88_ROOT/focused.xml" \
  > "$PHASE88_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 40 "$PHASE88_ROOT/focused.log"
```

组件测试中source的合成RV64 ELF明确不是源端真实构建或QEMU执行。真实目标GCC矩阵、策略拒绝和身份mutation测试也不能替代第2—4节。

## 2. 复用旧QEMU，显式升级构建profile

必须在第1节设置好PATH后执行；后续实验保留同一工具搜索环境。

```bash
python3 -m riscv2x86_py.controlled_system_backend upgrade-backend \
  --backend "$REPO/experiment/results/phase86-rQLWHm/controlled-system/backend.json" \
  --output "$PHASE88_ROOT/controlled-system" \
  > "$PHASE88_ROOT/backend-upgrade.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 50 "$PHASE88_ROOT/backend-upgrade.log"
```

成功后检查新profile：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['PHASE88_ROOT'])/'controlled-system/backend.json'
b=json.loads(p.read_text()); profile=b['buildProfile']
print('backendSchema',b['schemaVersion'])
print('backendIdentity',b['backendIdentity'])
print('relaxMode',profile['relaxMode'])
print('profileIdentity',profile['profileIdentity'])
print('buildCount',len(profile['records']))
for r in profile['records']:
    print(r['side'],r['operation'],r['optimization'],r['returnCode'],r['programDigest'])
PY
```

要求backend_status=0、v2、12条记录均returnCode=0。semanticApproval=false是正常的：构建能力不是翻译证明。
GCC 7.5可能拒绝首个driver配置，随后assembler配置只有完整矩阵通过才被选中。首个候选的拒绝不是最终失败。
若两种都失败，保留backend-upgrade.log和controlled-system/build-profile/probe-attempts.json，及build-profile-status.json，以及对应*.build.log和*.build.log.json；不要手工删参数或修改manifest。
重跑升级使用新的输出目录，不覆盖失败目录。升级不会修改旧backend或重建QEMU。

## 3. 原始输入完整生产验收

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$PHASE88_ROOT/controlled-system/backend.json"
export RV2X86_SYSTEM_CLANG="$CLANG10"
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --output "$PHASE88_ROOT/system" \
  > "$PHASE88_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 50 "$PHASE88_ROOT/system-driver.log"
python3 -m json.tool "$PHASE88_ROOT/system/run-status.json"
```

要求状态0、completedRoutes包含ecall和wfi、productionAcceptanceComplete=true、两条路线L0/L1/L2均verified且中央审计通过。
未配置bootstrap拒绝是预期；不能把approval批处理退出码1独立解释为证明失败，驱动器还会核查批准内容。
配置后程序仍使用profile中的原命令策略并重新检查实际产物。原始输入和profile内的构建示例不是同一次验证。

## 4. 合法重命名生产验收

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE88_ROOT/production.xml" \
  > "$PHASE88_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 60 "$PHASE88_ROOT/production.log"
```

要求2 passed、0 skipped。若输入工具不具备条件，不得计为生产成功。

## 5. 组合与最终无跳过回归

以上全部成功后，沿用docs/phase87-system-source-contract-closure.md第4节完整组合命令：
输出改为$PHASE88_ROOT/combined，使用本节新v2 backend及同一工具搜索环境；024/029选择此前已成功且身份仍有效的combined目录。
原32项不变时交叉检查30 verified、023/026非法输入拒绝，但验收依据是各项实际证据及suite-preservation，不是固定通过计数。

随后沿用该文档第5节选择024/029环境，并运行：

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang10 "$CLANG10" \
  --output "$PHASE88_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE88_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE88_ROOT/regression-driver.log"
tail -n 20 "$PHASE88_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE88_ROOT/regression-final/run-status.json"
```

要求零失败、零错误、零跳过、blockers为空。未传--suite，此命令不重复组合实验。

## 日志核查与验收边界

先看backend-upgrade.log及build-profile/profile.json，然后system/run-status.json的currentStage、blockers和failureDiagnostics。
具体程序构建有*.build.log（文本）、*.build.log.json（命令及真实退出码）、*.build.log.failure.json（失败侧和阶段）、*.build.json（通过的产物检查）。
通过预检或通过组件测试，不代表实际QEMU执行、逐维证据和中央closer通过。
开发环境没有真实交叉GCC／QEMU-system；真实宿主机构建和生产验收仍是交付后的必要验证，不预先声明完成。

## 开发环境结果

选定回归：1177 passed、43 skipped；相对Phase87新增24项，全部1196项既有测试的结果无变化。
更广历史语义集合：412 passed、10项既有失败、2 skipped；逐项结果无变化，不声明全仓库全绿。
43项选定回归跳过源于未选择真实SYSTEM后端或缺少Clang／llvm-mc／交叉GCC／QEMU等工具。
实际GCC 7.5+Binutils 2.30上的配置选择、完整RV64构建和QEMU生产执行仍须按上述宿主机步骤验证。

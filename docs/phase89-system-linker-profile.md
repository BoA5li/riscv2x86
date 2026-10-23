# Phase 89：受控 SYSTEM 链接器约束构建策略

基线：phase88-system-build-profile，82619cf16b6b0276f4d4a0a8f751abdc7a52f4ba。
新分支：phase89-system-linker-profile。

## 修订依据、约束与兼容性

用户实际GCC 7.5拒绝-mno-relax，Binutils 2.30汇编器也拒绝-Wa,-mno-relax。
诊断移除后者、保留-Wl,--no-relax后，ECALL/O0实际源构建成功且现有ELF检查通过。
该结果只用于提出配置候选；不导入诊断产物作为profile，不授予语义批准。

保留原两种策略，增加第三种独立候选：

| relaxMode | 源构建参数 |
| --- | --- |
| driver-norelax | -mno-relax、-Wl,--no-relax |
| assembler-norelax | -Wa,-mno-relax、-Wl,--no-relax |
| linker-norelax | -Wl,--no-relax |

第三种策略不声明汇编器不产生relaxation标记。它保留链接阶段禁用relaxation、
已审查启动／内核／链接实现、启动gp局部.option norelax保护及最终ELF检查。
每个源产物必须保持AUIPC+ADDI到__global_pointer$；不能仅凭参数存在认定启动正确。
官方依据：

- https://sourceware.org/binutils/docs-2.30/as/RISC_002dV_002dDirectives.html （gp及局部.option norelax）
- https://sourceware.org/binutils/docs-2.30/ld/Options.html （--no-relax及通过GCC传递-Wl参数）

准备和消费profile都核对已审查实现及其副本；自填implementationIdentity不能批准修改的boot／链接脚本。
预检、生产和L0继续共用命令生成器。策略按实际能力选择，不按案例、函数名或工具版本授权。
每种候选必须独立完成ECALL/WFI × O0/O2/O3 × source/target共12项构建。
任何后期失败、超时或无效ELF均不能生成成功profile／backend。
ELF检查仍包括架构／ABI、入口、装载、无动态加载器／未定义符号、BSS／栈和gp关系；不是完整程序语义证明。

构建policy升级为rv64i-lp64-bare-no-relax.v2；profile schema和backend v2不变。
旧策略含义不变；旧policy和旧recipe拒绝直接消费，必须upgrade-backend重新预检。
复用已验证QEMU和runtime，不修改旧manifest；新backend身份要求重新准备SYSTEM合同、批准和provider。
整个新profile及保留产物必须保存；后续使用同一工具搜索环境。
源模型身份、访问授权、翻译证明、L0/L1/L2与中央closer规则未放宽。
回归驱动器在Clang目录已处于PATH首位时原样保留PATH，避免重复前缀使有效profile因环境变化被拒绝；实际环境变化仍须重新预检。
支持域仍为受控单hart M-mode ECALL handler返回／MTIP预先pending的WFI，不扩展为Linux用户态、一般等待或L3。

## 1. 更新和定向回归

在已激活的.venv-l2中逐块执行。状态非0先检查日志，不继续依赖步骤；不使用set -e或exit。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase89-system-linker-profile
git switch --track origin/phase89-system-linker-profile
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export PATH="$(dirname "$CLANG10"):$PATH"
export PHASE89_ROOT="$(mktemp -d "$REPO/experiment/results/phase89-XXXXXX")"
printf '%s\n' "$PHASE89_ROOT"
cmake --build build -j2 > "$PHASE89_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 25 "$PHASE89_ROOT/build.log"
```

若本地已有该分支，使用git switch phase89-system-linker-profile。

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_system_build_profile.py \
  pytools/tests/test_privileged_source_completion.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_system_preparation.py \
  pytools/tests/test_system_deployment.py \
  pytools/tests/test_system_instruction_ingress.py \
  --junitxml="$PHASE89_ROOT/focused.xml" \
  > "$PHASE89_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 40 "$PHASE89_ROOT/focused.log"
```

组件测试中source的合成RV64 ELF明确不是源端真实构建或QEMU执行。真实目标GCC矩阵、策略拒绝和身份mutation测试也不能替代第2—4节。

## 2. 复用旧QEMU，显式升级构建profile

必须在第1节设置好PATH后执行；后续实验保留同一工具搜索环境。

```bash
python3 -m riscv2x86_py.controlled_system_backend upgrade-backend \
  --backend "$REPO/experiment/results/phase86-rQLWHm/controlled-system/backend.json" \
  --output "$PHASE89_ROOT/controlled-system" \
  > "$PHASE89_ROOT/backend-upgrade.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 50 "$PHASE89_ROOT/backend-upgrade.log"
```

成功后检查新profile：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['PHASE89_ROOT'])/'controlled-system/backend.json'
b=json.loads(p.read_text()); profile=b['buildProfile']
print('backendSchema',b['schemaVersion'])
print('backendIdentity',b['backendIdentity'])
print('policy',profile['policy'])
print('relaxMode',profile['relaxMode'])
print('profileIdentity',profile['profileIdentity'])
print('buildCount',len(profile['records']))
for r in profile['records']:
    print(r['side'],r['operation'],r['optimization'],r['returnCode'],r['programDigest'])
PY
```

要求backend_status=0、v2、12条记录均returnCode=0。semanticApproval=false是正常的：构建能力不是翻译证明。
三种候选按顺序独立探测；前两种拒绝不是最终失败。当前GCC 7.5／Binutils 2.30预计选择linker-norelax，但只有完整12项矩阵通过才可确认；不能按版本强制选择。
若三种都失败，保留backend-upgrade.log和controlled-system/build-profile/probe-attempts.json，及build-profile-status.json，以及对应*.build.log和*.build.log.json；不要手工删参数或修改manifest。
重跑升级使用新的输出目录，不覆盖失败目录。升级不会修改旧backend或重建QEMU。

## 3. 原始输入完整生产验收

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$PHASE89_ROOT/controlled-system/backend.json"
export RV2X86_SYSTEM_CLANG="$CLANG10"
python3 experiment/run_controlled_system_routes.py \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --output "$PHASE89_ROOT/system" \
  > "$PHASE89_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 50 "$PHASE89_ROOT/system-driver.log"
python3 -m json.tool "$PHASE89_ROOT/system/run-status.json"
```

要求状态0、completedRoutes包含ecall和wfi、productionAcceptanceComplete=true、两条路线L0/L1/L2均verified且中央审计通过。
未配置bootstrap拒绝是预期；不能把approval批处理退出码1独立解释为证明失败，驱动器还会核查批准内容。
配置后程序仍使用profile中的原命令策略并重新检查实际产物。原始输入和profile内的构建示例不是同一次验证。

## 4. 合法重命名生产验收

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE89_ROOT/production.xml" \
  > "$PHASE89_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 60 "$PHASE89_ROOT/production.log"
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
  --output "$PHASE89_ROOT/combined" \
  > "$PHASE89_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE89_ROOT/combined-driver.log"
python3 -m json.tool "$PHASE89_ROOT/combined/run-status.json"
python3 -m json.tool "$PHASE89_ROOT/combined/suite-preservation.json"
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
  --output "$PHASE89_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE89_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE89_ROOT/regression-driver.log"
tail -n 20 "$PHASE89_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE89_ROOT/regression-final/run-status.json"
```

要求零失败、零错误、零跳过、blockers为空。未传--suite，此命令不重复组合实验。

## 日志核查与验收边界

先看backend-upgrade.log及build-profile/profile.json，然后system/run-status.json的currentStage、blockers和failureDiagnostics。
具体程序构建有*.build.log（文本）、*.build.log.json（命令及真实退出码）、*.build.log.failure.json（失败侧和阶段）、*.build.json（通过的产物检查）。
通过预检或通过组件测试，不代表实际QEMU执行、逐维证据和中央closer通过。
开发环境没有真实交叉GCC／QEMU-system；真实宿主机构建和生产验收仍是交付后的必要验证，不预先声明完成。

## 开发环境结果

选定route-contract回归合计1203 passed、43 skipped、0 failed（分组执行，重复项使用最新结果）。
构建策略测试扩展为47项，回归驱动器测试14项；与Phase88相比，构建策略测试之外1196项既有测试结果均未变化。
源端使用明确标记的合成RV64 ELF协议fixture，目标端执行真实native GCC构建；不能替代真实交叉构建或QEMU生产执行。
43项跳过是未选择实际SYSTEM后端或缺少Clang／llvm-mc／交叉GCC／QEMU等生产工具，不计为生产成功。
本轮未重跑全仓库历史测试；不声明全仓库全绿。宿主机仍须完成12项真实构建、原始与重命名输入生产验收、组合和无跳过选定回归。

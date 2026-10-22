# Phase 86：ECALL／WFI 的显式受控 M-mode 路线

基线 `36426b1c7611df1d897a0ac2471c032b48302dce`，分支
`phase86-system-instruction-authority`。本轮扩展 016／022 对应的操作种类，
按实际机器码及真实 compiler fragment 绑定，不使用案例编号、函数名或路径授予许可。

## 支持范围与完成声明

| 操作 | 本轮明确支持的域 | 不作出的声明 |
| --- | --- | --- |
| ECALL | QEMU 7.2 virt、单 hart、M-mode、bare、RV64I+Zicsr；无参数无结果的单条 volatile/memory asm；受控 handler 保存恢复全部整数寄存器、推进 mepc 4 字节、MRET 返回 | Linux syscall、任意服务 ABI、任意函数内部位置、通用特权状态翻译 |
| WFI | 同一系统域；本地 MTIP 在指令前已待决、MTIE=1、全局 MIE=0；允许体系结构规定的提前恢复，目标执行 PAUSE 并保持对应逻辑状态 | 未来中断到达、任意调度器、无限等待活性、跨 hart 事件、功耗或时延等价 |
| 024／029 | 沿用局部同步／独立受控读取轨迹配置 | 跨 hart 代码发布、原生严格 TIME、完整物理时钟模型 |

目标是 x86 进程内的独立逻辑 M 状态运行时，不是 x86 原生特权／Linux 环境等价。
所有新路线报告 `originalLinuxUserEquivalent=false`、独立 environment identity 和 L3 未验证。
裸批处理没有显式环境时仍应拒绝 ECALL/WFI；不能用自动选择 M-mode 消除 unsupported。

代码已接入合同准备、正常 Phase 6C/6D/6F、实际 kernel/native 构建、L0/L1/L2、
中央证据审计和组合保持性检查。开发主机只有原生 GCC/ar，缺 LLVM frontend、
交叉 GCC 和 QEMU；真实 QEMU 生产验收在此主机**尚未完成**。组件通过不能替代下面的实验。
机器可读记录见 `experiment/baselines/phase86/validation-summary.json`。

## 实现与机制依据

* 精确解码 ECALL/WFI 的 32 位编码；无执行权威时保留不完整 typed effects，禁止猜测允许访问或不会 trap。
* 新 SYSTEM authority 绑定源码、fragment、机器码、执行事实、handler／事件关系；只有满足 M/bare 支持域才完成元数据。
* 环境 V2 区分虚拟内存与虚拟化；ECALL 允许独立 trap-only 合同，不虚构 Linux ABI。旧 V1 可检查，不能为新生产路线授予许可。
* 显式 deployment 验证实现源码、header、archive、capability 和 renderer 的一致性；语义 registry 存在本身不安装 helper。
* 严格差分额外比较有序外部事件和可观察效果；通用 Phase-6 v2 候选按生产者使用的 FNV 摘要重放。
* `runtime/system/controlled_system_boot.S` 的 256 字节 frame 保存并恢复 x1、x3…x31，x2 由平衡的栈调整恢复；C handler 不使用 F/V。16 字节栈对齐。
* QEMU 源端读取实际 mcause、mtval、mepc-next 关系、mstatus 的 MIE/MPIE/MPP、mie/mip 和事件序列。目标执行实际注册 helper；不以相同返回值代替事件与状态。
* 准备、批准、实际执行与最终验证分开；超时保留 partial stdout/command，结论 inconclusive。错误状态、事件次数／顺序、工具、产物及外层环境归属不会成为 verified。
* 注册机制固定经过核查的实现摘要；改变实现后单纯重新计算 hash 不会自动得到新机制审查。目标 archive 还会独立重建并比较字节。

机制审查定位：RISC-V Privileged 1.12 的 ECALL、MRET、WFI；
[规范发布](https://github.com/riscv/riscv-isa-manual/releases/tag/Priv-v1.12)；
QEMU 固定提交 `b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56` 的
[trap 实现](https://github.com/qemu/qemu/blob/v7.2.0/target/riscv/cpu_helper.c)、
[MRET/WFI helper](https://github.com/qemu/qemu/blob/v7.2.0/target/riscv/op_helper.c)、
`riscv_cpu_has_work`、`hw/riscv/virt.c`、CLINT 和 SiFive test finisher。
ECALL 在该 QEMU 路径产生 M cause 11、tval 0；MRET 恢复 MIE、置 MPIE、清 MPP。
WFI 的局部待决事件与全局中断允许位分别处理。有限探针不替代这些机制及域前提。

## 1．更新与准备

逐段执行、检查状态再继续。不使用 `set -e`、`exit`、reset 或 clean。保留已有本地修改。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
git status --short
git fetch origin phase86-system-instruction-authority
git switch --track origin/phase86-system-instruction-authority
git rev-parse HEAD

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export PATH="$(dirname "$CLANG10"):$PATH"
export PHASE86_ROOT="$(mktemp -d "$REPO/experiment/results/phase86-XXXXXX")"
printf 'PHASE86_ROOT=%s\n' "$PHASE86_ROOT"
cmake --build build -j2 > "$PHASE86_ROOT/frontend-build.log" 2>&1
FRONTEND_STATUS=$?
printf 'frontend_status=%s\n' "$FRONTEND_STATUS"
tail -n 25 "$PHASE86_ROOT/frontend-build.log"
```

已有同名本地分支时使用 `git switch phase86-system-instruction-authority`，然后
`git pull --ff-only origin phase86-system-instruction-authority`。不强行覆盖未提交修改。

## 2．构建独立系统后端

复用已追溯的 QEMU 源仓库，创建独立 worktree/build，不修改 `/usr/local/bin/qemu-riscv64`，
也不修改现有 TIME backend。需要系统构建依赖以及 `riscv64-linux-gnu-gcc`、GCC、ar。
源编译器必须实际接受 RV64I 的 CSR 指令；工具先探测现代／旧版 ISA 拼写并记录结果。

```bash
python3 -m riscv2x86_py.controlled_system_backend backend \
  --qemu-source "$REPO/qemu" \
  --output "$PHASE86_ROOT/controlled-system" --jobs 2 \
  > "$PHASE86_ROOT/system-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 40 "$PHASE86_ROOT/system-backend.log"
python3 -m json.tool "$PHASE86_ROOT/controlled-system/build-status.json"
```

只有状态 0、`backend.json` 存在且构建每步成功时继续。`semanticApproval=false` 正常：构建不授予语义批准。
若输出目录已存在，选择新目录，不覆盖既有产物。构建失败查看该目录的 configure/compile/版本及探测日志。

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$PHASE86_ROOT/controlled-system/backend.json"
python3 -m json.tool "$RV2X86_CONTROLLED_SYSTEM_BACKEND"
```

## 3．原始输入的独立生产验收

```bash
python3 experiment/run_controlled_system_routes.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" --clang "$CLANG10" \
  --backend "$RV2X86_CONTROLLED_SYSTEM_BACKEND" \
  --source "$REPO/experiment/generated-suite/case_016_bdfe6f1df9.c" \
  --source "$REPO/experiment/generated-suite/case_022_940af6ef05.c" \
  --output "$PHASE86_ROOT/system" \
  > "$PHASE86_ROOT/system-driver.log" 2>&1
SYSTEM_STATUS=$?
printf 'system_status=%s\n' "$SYSTEM_STATUS"
tail -n 40 "$PHASE86_ROOT/system-driver.log"
python3 -m json.tool "$PHASE86_ROOT/system/run-status.json"
```

要求状态 0、两个 completedRoutes、`productionAcceptanceComplete=true`；每条路线 L0/L1/L2 verified、
provider audit 成功。bootstrap／approval 可以暂时非零，但必须取得真实编译报告和获批候选，最终 configured 不能停在它们。
缺失文件、错误指令形态或更宽函数范围会明确拒绝，不要改状态为成功。

## 4．合法重命名生产回归

```bash
python3 -m pytest -vv -rs pytools/tests/test_controlled_system_production.py \
  --junitxml="$PHASE86_ROOT/system-production.xml" \
  > "$PHASE86_ROOT/system-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 45 "$PHASE86_ROOT/system-production.log"
```

必须两项通过、零跳过、状态 0。测试使用 inputs 子目录和兄弟 production 输出，保留 Phase 85 的隔离约束。
这是实际 frontend→证明→kernel/native→中央审计；组件测试中的模拟 source 协议不计为生产通过。

## 5．与 024／029 组合验收

选择**已成功验收、工具和源码身份仍有效**的 024／029 combined 目录。下面路径来自先前实验；
如你已在 Phase 85 重新生成，请替换为最新成功目录。旧运行中绑定的原始绝对路径和 backend 必须继续存在。

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
  --output "$PHASE86_ROOT/combined" \
  > "$PHASE86_ROOT/combined-driver.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 40 "$PHASE86_ROOT/combined-driver.log"
python3 -m json.tool "$PHASE86_ROOT/combined/run-status.json"
python3 -m json.tool "$PHASE86_ROOT/combined/suite-preservation.json"
python3 -m json.tool "$PHASE86_ROOT/combined/suite-configured/batch-evaluation.json"
```

驱动强制同一源码 inventory、原 verified 保持性、新选操作 verified、中央审计。若原 32 例未变且
四条路线均有效，应有 30 verified，023／026 仍为非法输入失败；不要用这个计数代替各项证据。
native、局部同步、受控 TIME 和 M-mode 的环境归属分别报告，不能称为 30 例全在 native Linux 等价。

## 6．最终无跳过回归

除了上述 SYSTEM 环境，保留／重新显式选择原有真实生产测试的 024／029 环境。
以下为先前使用的输入；若其身份或 CPU 前提改变，按旧准备流程重新生成。

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
  --output "$PHASE86_ROOT/regression-final" --require-no-regression-skips \
  > "$PHASE86_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 25 "$PHASE86_ROOT/regression-driver.log"
tail -n 20 "$PHASE86_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE86_ROOT/regression-final/run-status.json"
```

此命令针对版本控制的 route-contract 回归集合。要求零失败、零跳过、状态 0；
它不是“全仓库所有历史测试全绿”的替代声明。更广历史集合存在的既有失败也在本轮比较记录中单列。

## 7．失败时提取日志

先看 run-status.json 的 currentStage/blockers/failureDiagnostics。接着读取对应阶段日志，例如：

```bash
tail -n 80 "$PHASE86_ROOT/system/system-0-bootstrap.log"
tail -n 80 "$PHASE86_ROOT/system/system-0-approval.log"
tail -n 80 "$PHASE86_ROOT/system/system-0-configured.log"
cat "$PHASE86_ROOT/system/system-0-provider-audit.log"
find "$PHASE86_ROOT/system" -type f \
  \( -name evaluation-result.json -o -name '*build.log' -o -name index.json \) -print
```

将这些文件路径作为 `python3 -m json.tool "实际路径"` 的参数查看；字段说明不是 shell 命令。
evaluation-result.json 保留真实构建命令、异常、逐层 detail；L1/L2 detail 含两端 raw stdout/stderr、
实际 runner/产物摘要、事件与逻辑状态；provider invocation index 保留中央证据。
若没有进入 configured 阶段，不会存在该阶段文件，缺文件不能解释为已通过。

只有独立路线、合法变化、组合保持性、最终无跳过回归均实际通过，才可声明本轮选定域生产验收完成。

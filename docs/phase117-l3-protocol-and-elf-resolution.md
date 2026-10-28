# Phase117：LR/SC 生产链协议与 ELF 解析修复

本轮修复 Phase116 实验暴露的基础设施错误；不改变 LR/SC 语义证明、
L0–L3 判定、观察边界、机器归因、比较规则或独立重放要求。
生产端到端通过与否，仍须以下宿主机实验验证。

修复内容：

- `source_model.py` 的无条件 stdout 调试打印改为可选 DEBUG 日志。
  所有已注册意图生产 CLI 统一通过 `emit_json` 占有 stdout；嵌套诊断
  转到 stderr，成功 stdout 恰好一个 JSON 文档。消费者仍解析完整 stdout，
  不截取最后一行或跳过杂质。
- 每次外部生产器调用保留唯一、排他创建的 execution diagnostic，包含命令、
  requestIdentity、完整 stdout/stderr、摘要、退出码、耗时与超时信息。
  超时、启动失败、非法 JSON 同样保留。它们均 semanticApproval=false，
  不作为语义批准或观察证据。审计重放的诊断写入新的临时文件，
  不要求原证据目录可写。非法 JSON 的具体位置、诊断文件路径及摘要
  会经过 requirement staging 进入评估失败报告，不再将其误指为翻译报告损坏。
- ELF 保留每个符号的定义、绑定、可见性、表与条目索引。
  无关局部同名定义不阻止整个 ELF 加载。按名查询优先唯一外部定义，
  同一定义的 SYMTAB/DYNSYM 记录去重；真正查询歧义仍拒绝。
  函数类型、可执行节、字节范围与 ELF 表边界检查保留。
- LR/SC driver 在上游 staging 失败、程序 artifact 缺失或层证据不完整时
  明确记录 audit not_run 与原始失败，完成标志保持 false。
  已完整执行的 failed L3 反例仍允许独立审计，绝不转换为 verified。
- machine inspector 汇总报告、片段、二进制数量与错误；缺失源/目标机器证明、
  空目录或解析失败均返回非零，不再出现打印错误但退出码为零的情况。

以下命令使用 Bash，保留 `set +e`；失败只产生非零命令状态，不关闭交互终端。
每一步通过后再执行下一步；失败时保留本轮目录，不在相同输出目录重跑。

## 1. 更新与环境

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase117-l3-protocol-and-elf-resolution
git switch --track origin/phase117-l3-protocol-and-elf-resolution
git branch --show-current
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE117_ROOT="$(mktemp -d "$REPO/experiment/results/phase117-XXXXXX")"
export CONTROL_BACKEND="$REPO/experiment/results/phase108-VWL1Ko/control-backend/backend.json"
printf 'PHASE117_ROOT=%s\n' "$PHASE117_ROOT"
git rev-parse HEAD > "$PHASE117_ROOT/git-head.txt"
cmake --build build > "$PHASE117_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE117_ROOT/build.log"
```

若本地已有同名分支，使用 `git switch phase117-l3-protocol-and-elf-resolution`，
核对 HEAD 与本轮公布提交相同。不要丢弃工作区修改或清理旧结果来强行切换。

## 2. 相关回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_requirement_staging.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_atomic_retry.py \
  pytools/tests/test_l3_control_backend.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_fence_trace.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_trace_driver.py \
  --junitxml="$PHASE117_ROOT/focused.xml" \
  > "$PHASE117_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$PHASE117_ROOT/focused.log"
```

要求零失败、零错误、零跳过。新增测试执行实际 GCC 多编译单元 ELF 链接、
真实 LR/SC 意图生产子进程、组合选择 CLI 的输出边界、严格响应拒绝、
原始诊断保留与上游失败传播。此处协议测试的 fixture 不代表真实 QEMU 生产验收。

## 3. 重新检查原始最终机器码

```bash
python3 experiment/inspect_lrsc_machine.py \
  --root "$REPO/experiment/results/phase115-BEXqoQ" \
  > "$PHASE117_ROOT/machine-preflight.txt" 2>&1
PREFLIGHT_STATUS=$?
printf 'machine_preflight_status=%s\n' "$PREFLIGHT_STATUS"
cat "$PHASE117_ROOT/machine-preflight.txt"
```

要求退出码 0、末尾汇总 complete=true、errors=[]，两个输入均具有源 RISC-V
与目标 x86 函数证明。若出现新机器规则拒绝，保存完整输出后分析，不能略过。
该步骤读取旧 L2 二进制，不修改旧证据，也不替代本轮生产程序的部署归因。

## 4. 验证依赖并重新校准 LR/SC backend

本轮修改了 LR/SC backend 固定的文件，必须创建新的 LR/SC manifest。
旧 68 份校准记录保留，不能修改旧 manifest 中的摘要。
现有基础/control manifest 若其固定文件未变且严格验证通过，可继续用作依赖。
这里实际调用验证器重新核查已有校准记录与工具，不靠手工改摘要。

```bash
python3 - <<'PY' > "$PHASE117_ROOT/control-validation.log" 2>&1
import os
from riscv2x86_py.l3_control_backend import validate
value = validate(os.environ['CONTROL_BACKEND'])
print('control_backend_verified:', value['backendIdentity'])
PY
CONTROL_STATUS=$?
printf 'control_validation_status=%s\n' "$CONTROL_STATUS"
cat "$PHASE117_ROOT/control-validation.log"

if [ "$CONTROL_STATUS" -eq 0 ]; then
  python3 -m riscv2x86_py.l3_lrsc_backend \
    --control-backend "$CONTROL_BACKEND" \
    --output "$PHASE117_ROOT/lrsc-backend" \
    > "$PHASE117_ROOT/lrsc-backend.log" 2>&1
  BACKEND_STATUS=$?
  printf 'lrsc_backend_status=%s\n' "$BACKEND_STATUS"
  tail -n 80 "$PHASE117_ROOT/lrsc-backend.log"
  if [ -f "$PHASE117_ROOT/lrsc-backend/build-status.json" ]; then
    cat "$PHASE117_ROOT/lrsc-backend/build-status.json"
  fi
else
  printf '依赖验证失败，保留日志并先定位；未启动 LR/SC 校准。\n'
fi
```

要求 stage=complete、complete=true、68 个 calibrationCompleted、无 error，
且 backend.json 存在。semanticApproval=false 正常：校准不授予翻译语义批准。
若旧 control 验证失败，先定位实际变化的固定文件，再按依赖关系新建相关 backend；
不要绕过验证器或更新旧摘要。

## 5. 两个原始输入完成 L0–L3

```bash
export RV2X86_L3_LRSC_BACKEND="$PHASE117_ROOT/lrsc-backend/backend.json"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 experiment/run_l3_lrsc_trace.py \
    --input "$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_LRSC_BACKEND" \
    --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --output "$PHASE117_ROOT/original-$NAME" \
    > "$PHASE117_ROOT/original-$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done
python3 experiment/inspect_lrsc_evaluation.py --root "$PHASE117_ROOT" \
  > "$PHASE117_ROOT/evaluation-summary.txt" 2>&1
cat "$PHASE117_ROOT/evaluation-summary.txt"
```

再次显式重放独立审计：

```bash
python3 - <<'PY' > "$PHASE117_ROOT/acceptance-audit.log" 2>&1
import json
import os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
from riscv2x86_py.l3_lrsc_route import audit_result
root = Path(os.environ['PHASE117_ROOT'])
failures = []
for name in ('lrsc_add_32', 'lrsc_add_64'):
    directory = root / ('original-' + name)
    try:
        state = json.loads((directory / 'run-status.json').read_text())
        print(name, json.dumps(state, ensure_ascii=False), flush=True)
        flags = ('executionComplete', 'independentResultAuditComplete', 'productionAcceptanceComplete')
        if state.get('currentStage') != 'complete' or state.get('blockers') or any(state.get(k) is not True for k in flags):
            raise ValueError('driver completion checks failed')
        paths = list(directory.glob('batch/cases/*/evaluation-result.json'))
        if len(paths) != 1:
            raise ValueError('evaluation report count must equal one')
        report = json.loads(paths[0].read_text())
        for audit in (audit_result, audit_evaluation):
            result = audit(report)
            print(audit.__name__, json.dumps(result, ensure_ascii=False), flush=True)
            if result.get('status') != 'verified':
                raise ValueError('independent audit not verified')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        failures.append(name + ': ' + type(exc).__name__ + ': ' + str(exc))
print('FAILURES:', failures, flush=True)
if failures:
    raise SystemExit(1)
PY
AUDIT_STATUS=$?
printf 'acceptance_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE117_ROOT/acceptance-audit.log"
```

要求两个 driver 均 0、L0–L3 verified、control/memory/synchronization 三维 verified、
完成标志均 true、blockers=[]，独立审计通过。仅翻译 emitted 不代表完成。
若失败，请提供 evaluation-summary.txt、run-status.json、相关日志。
协议失败另附报告旁唯一的 `.l3-intent-execution-*.json`，可直接看到完整原始输出。

## 6. 生产矩阵与后续兼容性

只有两个原始输入通过后，才启动九项生产矩阵，避免重复等待同一基础错误。

```bash
python3 -m pytest -vv -rs pytools/tests/test_l3_lrsc_production.py \
  --junitxml="$PHASE117_ROOT/lrsc-production.xml" \
  > "$PHASE117_ROOT/lrsc-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'lrsc_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 120 "$PHASE117_ROOT/lrsc-production.log"
```

要求 9 passed，零失败/错误/跳过；这些生产测试还核查改动层状态与原始轨迹被独立审计拒绝。
本轮不声称并发原子性、物理内存序、公平性或无界重试进展已被测量。

完成以上步骤后，再推进 AMO、fence、memory、control、scalar-program 组合兼容性。
因共享文件 `l3_trace_support.py` 已改变，旧 AMO/fence manifest 的固定依赖会过期，
需在新目录重新调用其 prepare CLI 校准；不能直接复用原机制选择文件来逃过校验。
memory/control/scalar-program 可先严格 validate，固定文件未变且验证通过才复用；
失败则按实际依赖新建。组合配置使用各 manifest 实际返回的 backendPath，
加上本轮 lrsc 路径，再执行既有 030/006/000/002/018 与独立审计回归。

## 本地核验记录与边界

开发环境的相关回归为 992 passed；随后对生产器失败诊断补充修订，
受影响协议、staging 与新增测试再次运行 64 passed。
两轮均无 failure/error/skipped，不能将有重复测试的两轮数量相加。
开发环境没有宿主机所需的 RISC-V 编译器与 QEMU，未把九项生产矩阵
或真实 68 项校准计为已通过；以上宿主机验收仍是发布后的完成条件。

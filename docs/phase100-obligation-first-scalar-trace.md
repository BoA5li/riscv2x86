# Phase100：独立属性义务与真实标量片段访存轨迹

基线：Phase99 `d4ccdca5ff59b2071fb85baa8f7c2111bec0cc3a`。
分支：`phase100-l3-obligations-and-scalar-trace`。

## 实现与声称范围

本轮接通一条有真实执行与独立审计的通用机制：完整获批、单函数、单片段、单次标量操作，函数接收一个 unsigned 64 位参数并返回 unsigned 64 位结果，编译器 scope 证明片段外不存在额外控制/访存操作。立即数是前轮已证明的静态输入，函数名/路径/案例号不参与许可。

`l3_property_obligations.analyze` 独立消费 typed L2 semantic profile、sidecar、effect proof 与 boundary。核验 fragment/proof 身份、source effects 和目标关系一致，以及跨族 shape 完整性。注册策略 `compiler-region-architectural-intent.v1` 要求片段的数据访存属性；显式控制或同步属性则保留为独立义务。事实不足仍 unresolved，不从空列表推断不适用。

`l3_trace_intent` 在上述义务确定后才选择普通访存或标量机制。不能覆盖的控制/同步义务保留在不完整 profile 中，且保留 programId 与具体原因。旧 `l3_memory_intent` 仍可显式使用；普通访存诊断细分为 access kind、authority、fragment、非原子域、对象/效果数量、关系与 runtime/ignored-state，而非单一 SINGLE_READ。

标量路线生成 intentKind=memory_access 的**真实验证任务**，不是 intent=none/not_applicable，也不虚构内存对象。合同 v3 的比较器为 `memory:empty-executed-region`，schema 不可降级。新 observation v2 使用 `samples`，旧访存 observation v1 的 `objects` 不变。

复用现有插件的 B/E/F 协议。必须捕获每次进入和退出、正确 token、地址区间、次数和无错误结束，才能判定零数据访存；空文件/未执行/partial/额外访问不能通过。部署继续核查获批目标源码、真实 L0 函数字节、zero-byte labels、链接后字节、独立重建及实际 runner。中央审计重新解析原始 capture/command、重放合同/义务、验证输入与源/目标结果、上下文与逐属性结论。

本轮没有修改 QEMU 插件或 backend builder，因此可继续使用完整校验通过的 Phase95 backend。新生产命令生成新的 producer manifest、profile、receipt、合同和执行结果，不复用旧案例证据。

L3 此处验证的是有限输入下成功执行的 compiler asm 区间内数据访存意图；值语义仍以翻译证明和 L2 为前提。取指、片段外效果、真实 cache/timing/prediction/speculation 不在本次声称范围。标量的 object-relative cache model 尚无适用对象域，显式选择时保留义务并拒绝，不能将其改成缓存等价。

多片段、多参数/其它类型、控制/同步真实观察器、复杂内存流、特权/CSR/受控时间的环境混合、所有 producer 工具故障的独立分层发布，仍是后续能力。配置冲突和单片段限制保持拒绝。这是整体方案的连续实现批次，不是所有 L3 属性已完成。

## 更新与环境

在已激活 `.venv-l2` 的 shell 中逐块执行；命令不使用 exit 或 set -e。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase100-l3-obligations-and-scalar-trace
git switch --track origin/phase100-l3-obligations-and-scalar-trace
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10=/usr/bin/clang-10
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE100_ROOT="$(mktemp -d "$REPO/experiment/results/phase100-XXXXXX")"
hash -r
printf 'PHASE100_ROOT=%s\n' "$PHASE100_ROOT"
command -v clang
ls -l "$RV2X86_L3_TRACE_BACKEND"
cmake --build build -j2 > "$PHASE100_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 35 "$PHASE100_ROOT/build.log"
```

要求构建退出0、Clang10及backend文件存在；否则先查对应日志。

## 相关检查

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_scalar_trace.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_route_applicability.py \
  pytools/tests/test_l3_provider_resolution.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_static_operand_production.py \
  --junitxml="$PHASE100_ROOT/focused.xml" \
  > "$PHASE100_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 65 "$PHASE100_ROOT/focused.log"
```

通过后才继续真实生产。无需每次重复全32项。

## 真实生产验收

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_scalar_trace_production.py \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE100_ROOT/production.xml" \
  > "$PHASE100_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 130 "$PHASE100_ROOT/production.log"
```

要求 **7 passed，0 skipped**：标量 addi67、slli18、addi-7 三项，加原读/写 × 不选/选择缓存模型四项。标量测试检查完整L0-L3、4次B/E与F 4 4 0 0、真实结果、无虚构对象、独立审计及篡改捕获拒绝。

## 原始输入

本次原始023/026**不要传 --cache-model**。预期从前轮 L3 unsupported 推进到完整的片段数据访存属性验证；任何失败仍应按实际日志定位，不预先视为正常拒绝。

```bash
for SOURCE in \
  "$REPO"/experiment/generated-suite/case_023_*.c \
  "$REPO"/experiment/generated-suite/case_026_*.c
do
  CASE_NAME="$(basename "$SOURCE" .c)"
  python3 experiment/run_l3_memory_trace.py \
    --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_TRACE_BACKEND" \
    --output "$PHASE100_ROOT/$CASE_NAME" \
    > "$PHASE100_ROOT/$CASE_NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
done
```

提取结果：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['PHASE100_ROOT'])
for directory in sorted(root.glob('case_*')):
    print('\nCASE:',directory.name)
    status=directory/'run-status.json'
    if status.is_file():
        d=json.loads(status.read_text())
        for key in ('currentStage','productionAcceptanceComplete','blockers','acceptance'):
            print(key, json.dumps(d.get(key),ensure_ascii=False))
    for path in sorted(directory.rglob('evaluation-result.json')):
        d=json.loads(path.read_text()); print('REPORT:',path)
        for key in ('status','reasonCodes','detail','orchestrationFailure','requirementStagingFailure'):
            print(key,json.dumps(d.get(key),ensure_ascii=False))
        for a in d.get('attempts',[]):
            print('translation',a.get('translationOutcome'))
            for layer in (a.get('validation') or {}).get('layers',[]):
                print('LAYER',layer.get('level'),layer.get('status'))
                if layer.get('status')!='verified':print(layer.get('detail'))
    log=directory/'batch.log'
    if log.is_file(): print('BATCH LOG:', '\n'.join(log.read_text(errors='replace').splitlines()[-20:]))
PY
```

要求两项 L0/L1/L2/L3 verified、独立审计通过、productionAcceptanceComplete=true。结果只能表述为上述有界属性验证成功，不能称为物理微架构严格等价。

## 后续次序

7项生产与原始输入通过后，恢复原已审查的016/022/024/029专用环境做兼容验收（不要与此backend强行混用），再做一次无跳过选定回归。新增两个测试文件已经列入 `verify_route_contracts.py`。随后推进下一类真实观察器及多片段，最终按属性与环境重新统计32项覆盖，不把 unsupported 或 not_applicable 计为实验 verified。

## 开发环境验证

- 相关L3/入口/配置/需求与前轮静态输入检查：427 passed、10 skipped。
- 复核 registry、合同、审计和观察样本后追加检查：161 passed；最后文档对应相关检查200 passed。
- 当前开发环境没有真实RISC-V工具链和双ISA QEMU backend；7项L3真实生产与3项立即数L2生产测试未在此环境执行，不替代主机验收。
- 对上传的两个真实 finding 执行独立义务和分派重放，均得到完整的 access_pattern 需求；这是静态重放，不是新的QEMU成功证据。

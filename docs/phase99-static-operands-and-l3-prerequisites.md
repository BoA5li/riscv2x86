# Phase99：静态操作数的完整 L2 消费与 L3 前提分类

基线 Phase98：`e822176f93616a92af3f30cf6391dd95ac542e1d`。本轮针对已确认的 023/026 前置阻塞完成一批通用实现，不宣称所有 L3 机制已实现。

## 修订内容

原 compiler literal closure 已能产生表达式 carrier，但通用 L2 boundary 仍读取原始不完整候选，且 canonical/observation 要求每个输入都有声明或动态参数，导致 arity mismatch、sidecar 缺失和效果关系为空。

本轮加入版本化 compiler-static-operand，绑定原始 AST 闭合、表达式、求值身份、值节点、值、位宽、signedness 和 GNU i/n 约束。只有独立重放的已闭合候选与原始 compiler candidate 一致时，才进入新 boundary。常量没有虚构声明、参数或运行时读取。

对应格式为：fragment boundary v3、canonical binding set v2、operand observation authority v3、L2 sidecar v6。没有常量时继续使用原格式；新载荷不能降级到旧格式。已实现内存左值 v5 原子路线保持独立。

Canonical consumer、sidecar、compiler provenance、观察计划和 provider applicability 均核对静态绑定。动态参数/返回值仍实际执行采集；常量投影明确标记 compiler_constant，是编译器静态见证而非客户机读取事件。错常量、错类型、重算 hash 的篡改及 schema 降级均须拒绝。当前只支持已有有界 literal/括号/一元正负闭合，不承诺任意常量表达式、转换、任意函数 scope 或零参数函数的新支持。

L3 ingress 将 compiler-binding-mismatch 与 effect-relation-required 分开。身份失败仍终止；仅缺效果关系时保存不完整 unknown + prerequisites_missing，无语义批准、无 producer receipt，允许正常产生 L2/L3 需求，保留前置缺口。真实 producer 工具/协议错误仍严格失败；本轮尚未把所有此类故障改造成独立的分层发布协议。

普通访存 L3 adapter 在调用其 memory_spec 之前读取 requirement eligibility。不适用输入保留 producer 的具体理由，不再用 generic single-read 错误覆盖它。它仍不会为算术、控制、原子或多片段输入授予 L3 许可。

## 本轮验收目标

1. 原始及重命名的立即数输入完成真实 L0/L1/L2，静态角色与实际动态结果均被中央验证。
2. 明确缺少关系的输入保存前提不足状态，不伪造 relation/intent=none。
3. 原普通读写、原子、CSR/同步等正确路线不退化。
4. L3 属性框架、控制流/同步/并发/物理实验及多片段完整支持仍按总方案后续推进。本轮 L2 成功不能当成 L3 完成。

## 1. 更新、环境与构建

在已激活 .venv-l2 的 shell 中逐块执行。所有输出用新目录，不覆盖旧证据；不使用 shell exit 或 set -e。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase99-static-operands-and-l3-prerequisites
git switch --track origin/phase99-static-operands-and-l3-prerequisites
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10=/usr/bin/clang-10
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE99_ROOT="$(mktemp -d "$REPO/experiment/results/phase99-XXXXXX")"
hash -r
printf 'PHASE99_ROOT=%s\n' "$PHASE99_ROOT"
command -v clang
clang --version
cmake --build build -j2 > "$PHASE99_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 35 "$PHASE99_ROOT/build.log"
```

要求 Clang10、构建退出 0；否则先查日志。

## 2. 相关回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_static_operand_production.py \
  pytools/tests/test_automatic_l2_operand.py \
  pytools/tests/test_l2_operand_observation_authority.py \
  pytools/tests/test_canonical_l2_operand.py \
  pytools/tests/test_canonical_observation_materializer.py \
  pytools/tests/test_l2_operand_join_preconditions.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_requirement_staging.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_l3_memory_trace.py \
  --junitxml="$PHASE99_ROOT/focused.xml" \
  > "$PHASE99_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 55 "$PHASE99_ROOT/focused.log"
```

无失败后进入真实生产测试；无需先重复全部32项。

## 3. 真实立即数生产测试

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_static_operand_real_production.py \
  --junitxml="$PHASE99_ROOT/production.xml" \
  > "$PHASE99_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE99_ROOT/production.log"
```

要求 **3 passed、0 skipped**，覆盖 renamed addi 67、slli 18、addi -7。每项独立检查 L0/L1/L2、无虚构声明的静态角色、compiler provenance 重放及中央逐维 L2 结果。L3 没有在此测试中获准，不应据此报为 L3 成功。若失败，保留 pytest 对应 production 目录，读取 evaluation-result.json 的首个非 verified 层和 translated_report.json 的 boundary/decision/sidecar。

## 4. 原始023/026的前置验收

```bash
for SOURCE in \
  "$REPO"/experiment/generated-suite/case_023_*.c \
  "$REPO"/experiment/generated-suite/case_026_*.c
do
  CASE_NAME="$(basename "$SOURCE" .c)"
  python3 -m riscv2x86_py.automatic_batch_cli \
    --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
    --output-directory "$PHASE99_ROOT/original-$CASE_NAME" \
    --jobs 1 --timeout-seconds 180 \
    > "$PHASE99_ROOT/original-$CASE_NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
done
```

这里未强制 L3，首先要求两个原始输入 L0/L1/L2 verified。之前已证明其 C/asm 输入合法，不沿用旧的 invalid_source_input 分类。

提取结果：

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['PHASE99_ROOT'])
for path in sorted(root.glob('original-*/cases/*/evaluation-result.json')):
    report=json.loads(path.read_text())
    print('\nREPORT:',path)
    print('status:',report.get('status'),'reasons:',report.get('reasonCodes'))
    print('stagingFailure:',report.get('requirementStagingFailure'))
    for attempt in report.get('attempts',[]):
        print('translation:',attempt.get('translationOutcome'))
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            print('LAYER:',layer.get('level'),layer.get('status'))
            if layer.get('status') not in ('verified','not_run'):print(layer.get('detail'))
for path in sorted(root.glob('original-*/cases/*/work/translation-work/translated_report.json')):
    print('\nTRANSLATION:',path)
    for finding in json.loads(path.read_text()).get('findings',[]):
        a=finding.get('approvalArtifact') or {}
        print('boundary:',(a.get('l2FragmentOperandBoundary') or {}).get('complete'))
        print('materialization:',a.get('l2MaterializationDecision'))
        sidecar=a.get('l2AuthoritySidecar') or {}
        print('sidecar schema:',sidecar.get('schemaVersion'),'complete:',sidecar.get('complete'))
        print('static operands:',[x for x in sidecar.get('operands',[]) if 'staticOperand' in x])
PY
```

## 5. 有针对性的L3及兼容检查

上述步骤通过后，才将023/026交给原 run_l3_memory_trace.py，使用现有 Phase95 calibrated backend、新的 output 目录。预期需求发布不再因空效果关系中断；在普通访存 L3 配置下，仍应明确报告该机制不适用，不能要求它们变为 L3 verified。

再重跑 Phase98 的四项普通读写真实生产测试，要求 4 passed、0 skipped；以及原专用环境的兼容测试。新旧产物、profile和receipt不混用，不能手动修改 hash。暂不重复全32项；待后续属性路线完成再进行阶段性覆盖。

最终回归仍用 verify_route_contracts.py --require-no-regression-skips，传入 --clang10 /usr/lib/llvm-10/bin/clang，恢复此前已审查的 backend/声明/runner 配置。是否最终无跳过应单独报告。

## 开发环境验证记录

- 选定集成回归：1571 passed、50 skipped；跳过包含本环境缺少的真实工具链/显式生产配置，不等于无跳过验收。
- 最后相关检查（含静态绑定、独立 join、L3 ingress、原子及多片段候选兼容）：180 passed、3 skipped。三项跳过均为新增真实立即数生产测试。
- 本环境没有 Clang/LLVM-MC、RISC-V GCC 和 QEMU，因此尚未验证原始023/026或新立即数路线在用户工具链上的完整执行。必须以以上主机实验补齐，不将本地 fixture 测试替代真实生产验收。

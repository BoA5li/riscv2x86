# Phase101：多参数标量调用合同与原子 L3 前置事实重放

基线：Phase100 `d4d9783b02e65a088c165bbf11e936fc05fc8565`。
分支：`phase101-l3-scalar-calls-atomic-eligibility`。

## 本轮实现与边界

- 标量 L3 从一个 unsigned64 参数扩展为 1—4 个 signed/unsigned64 整数参数及 signed/unsigned64 返回值。参数顺序、声明、编译器 C 类型、类型身份、位宽与符号性来自闭合编译器 authority 和函数快照，不依据文件名、指令名称或测试编号授权。
- `l3_scalar_call` 定义调用签名、ABI 域和确定性输入向量。保留实际 canonical C 类型以维持跨编译单元函数类型兼容；signed 输入通过范围内转换与减法生成，不依赖超范围 unsigned→signed 转换。结果按定义明确的 unsigned64 转换记录。参数数目、位宽和类型的未支持域仍明确拒绝。
- 新 scalar experiment v4、deployment v2、observation v3、sample v2 绑定向量和 samplePlan。旧 v3 单参数合同仍按原格式严格重放；普通读写合同与缓存模型不变。新向量合同不能降级成旧合同。
- 实际执行记录的参数、样本、顺序、planIdentity、token 与返回值均独立解析。实际源码、获批替换、L0 函数字节、zero-byte labels、最终执行镜像、原始 B/E/F 捕获、中央比较与独立验收要求继续生效。空日志不是零访问证据。
- 原子义务分类复用 canonical atomic proof，重建专门 L2 authority、重新计算 materializability，并重放通用边界的 program/function 身份。通用 scalar 边界不完整不再误阻塞完整原子 authority；它不会被改写为 complete。编译器函数来自 ingress 已验证快照，且进入可重放 producer request。
- 030 的本轮目标是产生正确内存访问与同步义务，然后明确报告缺少 synchronization 机制。没有新增原子/并发观察器，不应期待 030 L3 verified。
- 回归驱动增加 `--regression-timeout-seconds`，默认1800保持兼容；可显式选7200，且写入状态文件。仅改变外层预算，不改变测试判定或单用例限制。

声称范围仍为 listed-input-vectors-only 的 compiler asm region 成功执行数据访问意图。没有物理缓存、时序、预测、推测执行、片段外效果或全部输入等价的声称。未新增控制流、同步、多片段和特权 L3 观察器。

## 1. 更新、工具选择、构建

以下每块独立执行；不要使用 set -e 或 exit。已激活原 `.venv-l2`。保留已有实验结果与已审核专用环境配置。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase101-l3-scalar-calls-atomic-eligibility
git switch --track origin/phase101-l3-scalar-calls-atomic-eligibility
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10=/usr/lib/llvm-10/bin/clang
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE101_ROOT="$(mktemp -d "$REPO/experiment/results/phase101-XXXXXX")"
hash -r
printf 'PHASE101_ROOT=%s\n' "$PHASE101_ROOT"
command -v python3
command -v clang
clang --version
command -v cmake
cmake --version
ls -l "$RV2X86_L3_TRACE_BACKEND"
cmake --build build > "$PHASE101_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE101_ROOT/build.log"
```

构建必须退出0。不要因旧 backend 文件存在便认定有效；生产链会完整验证其绑定。QEMU 插件和 backend builder 本轮未改动。

## 2. 定向与反向检查

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_scalar_call.py \
  pytools/tests/test_l3_atomic_eligibility.py \
  pytools/tests/test_l3_scalar_trace.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_provider_resolution.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_route_contract_regression_runner.py \
  --junitxml="$PHASE101_ROOT/focused.xml" \
  > "$PHASE101_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE101_ROOT/focused.log"
```

要求无 failure/error。新增本地测试包括有符号转换及 UBSan 原生执行、向量篡改、参数交换、合同降级、原子 proof/type/object/program/function 不一致与伪造 persisted executable 的拒绝。它们不替代双 ISA 生产验收。

## 3. 真实双 QEMU 生产验收

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_scalar_trace_production.py \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE101_ROOT/production.xml" \
  > "$PHASE101_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 130 "$PHASE101_ROOT/production.log"
```

预期 **11 passed，0 skipped**：原3项单参数立即数、4项双参数 sub/srl/sra/slt（unsigned、signed、signed入unsigned出）、原读写×是否选择缓存模型4项。要求完整L0—L3及独立验收。任何失败先查日志，不继续认定修订完成。

## 4. 原始14项及原子030诊断

不向标量传 `--cache-model`。这些编号仅选择回归输入，不参与实现许可。

```bash
for INDEX in 003 005 007 008 010 012 014 015 017 019 021 025 028 031 030
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    CASE_NAME="$(basename "$SOURCE" .c)"
    python3 experiment/run_l3_memory_trace.py \
      --input "$SOURCE" \
      --frontend "$RISCV2X86_TEST_FRONTEND" \
      --backend "$RV2X86_L3_TRACE_BACKEND" \
      --output "$PHASE101_ROOT/$CASE_NAME" \
      > "$PHASE101_ROOT/$CASE_NAME.log" 2>&1
    CASE_STATUS=$?
    printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
  done
done
```

14项标量目标：emitted、L0/L1/L2/L3 verified、productionAcceptanceComplete=true、独立验收verified。不可提前保证，真实工具链暴露的新错误仍需定位。

030目标：L0—L2继续通过；L3明确保留 memory.fragment-access 与 synchronization.fragment-events，拒绝原因推进为 `L3_TRACE_REQUIRED_MECHANISM_UNAVAILABLE:synchronization`，而非 `L3_OBLIGATION_FACTS_INCOMPLETE`。退出2且不完成L3验收符合本轮边界；不是整个030最终修订目标已完成。

## 5. 统一提取结果

```bash
python3 - <<'PY' > "$PHASE101_ROOT/results-summary.txt" 2>&1
import json, os
from pathlib import Path
import xml.etree.ElementTree as ET
root=Path(os.environ['PHASE101_ROOT'])
for name in ('focused.xml','production.xml'):
    path=root/name
    print('\nXML:',path)
    if not path.is_file():
        print('missing'); continue
    cases=list(ET.parse(path).getroot().iter('testcase'))
    print('tests:',len(cases))
    for tag in ('failure','error','skipped'):
        matched=[c for c in cases if c.find(tag) is not None]
        print(tag,len(matched))
        for c in matched:
            e=c.find(tag); print(c.get('name'),e.get('message'),e.text)
for directory in sorted(root.glob('case_*')):
    if not directory.is_dir(): continue
    print('\nCASE:',directory.name)
    status=directory/'run-status.json'
    if status.is_file():
        d=json.loads(status.read_text())
        for key in ('currentStage','productionAcceptanceComplete','blockers','acceptance'):
            print(key,json.dumps(d.get(key),ensure_ascii=False))
    reports=sorted(directory.rglob('evaluation-result.json'))
    print('report_count',len(reports))
    for path in reports:
        d=json.loads(path.read_text()); print('REPORT:',path)
        for key in ('status','reasonCodes','detail','orchestrationFailure','requirementStagingFailure'):
            if d.get(key) is not None:print(key,json.dumps(d[key],ensure_ascii=False))
        for attempt in d.get('attempts',[]):
            print('translation',attempt.get('translationOutcome'))
            for layer in (attempt.get('validation') or {}).get('layers',[]):
                print('LAYER',layer.get('level'),layer.get('status'))
                if layer.get('status')!='verified':print(layer.get('detail'))
    if not reports:
        log=directory/'batch.log'
        if log.is_file():print(log.read_text(errors='replace')[-12000:])
PY
SUMMARY_STATUS=$?
printf 'summary_status=%s\n' "$SUMMARY_STATUS"
cat "$PHASE101_ROOT/results-summary.txt"
```

## 6. 兼容性与最终回归

前面通过后才进行。先重验已有6项（000/001/004/009/023/026）；读写4项可沿用明确选择的缓存模型，023/026不选对象相对缓存模型。然后保留并验证原已审核的受控系统、时间、同步环境变量，执行一次选定无跳过回归：

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 "$CLANG10" \
  --output "$PHASE101_ROOT/regression-final" \
  --regression-timeout-seconds 7200 \
  --require-no-regression-skips \
  > "$PHASE101_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 70 "$PHASE101_ROOT/regression-driver.log"
if [ -f "$PHASE101_ROOT/regression-final/run-status.json" ]; then
  cat "$PHASE101_ROOT/regression-final/run-status.json"
fi
```

没有配置真实 backend 的生产检查应显示 skipped，不能称无跳过验收。不要凭本文件自动设置旧专用合同路径；它们必须仍满足当前代码及环境绑定。

本批通过后，再推进控制流、同步/原子观察、多片段组合与受控环境 L3 接入；未实现的属性不能改为不适用或删去义务。

## 开发环境验证记录

- 相关 L3、batch、原子 authority、materialization、静态操作数及回归驱动检查：466 passed，11 skipped，0 failure/error。
- 11项跳过均为显式双ISA QEMU后端未选择的真实生产检查；当前开发环境没有完整 RISC-V 工具链与已校准的双ISA运行后端。不能将这些检查记为生产通过。
- 原生 GCC + UBSan 实际编译运行覆盖1—4参数、signed/unsigned混合及signed结果；这仅验证调用/记录实现，不替代源RISC-V与目标x86的生产执行。
- 未重新执行全量回归和32项真实语料；按上述主机步骤完成后才能评价真实覆盖变化。

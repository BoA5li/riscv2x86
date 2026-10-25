# Phase98：按实际访问类型消费 L2 内存范围

基于 Phase97 `0640caddf1b7fc3cfcf72b85ff1c0ff8f86e8c9c`。本轮修复已复现的纯写入接入错误；真实双端完整验收仍须在实验主机执行。

## 根因与改动

真实 `bind_memory_object_authority()` 对纯写入生成 `readableRanges=[]`、`writableRanges=[[offset,offset+width]]`。Phase97 的 L3 `memory_spec()` 却无条件要求读取范围覆盖，导致两项真实写入测试在 L0/L1/L2 verified 后以 `L3_MEMORY_OBJECT_DOMAIN_INCOMPLETE` 停在 L3 准备阶段。定向夹具从读取修改而来，保留了读取范围，漏检了这处生产/消费冲突。

本轮：

- 公共对象、边界、对齐、来源和生命周期检查保持。
- load 检查读取范围；store 检查写入范围，不要求纯写入具有读取范围。
- 两种范围都检查整数对、对象内边界、排序和唯一性；非法结构以原错误码拒绝，producer 继续产生前提不足状态，不产生 intent=none。
- 不更改 L2 对象生产函数，不虚构范围、不修改证明或合同格式。原读取路线的其他限制保持。
- 修正写入夹具；使用实际 L2 对象生产函数连接 L3 intent/requirements，覆盖 load/store、偏移 0/8/24、带模型/不带模型；消费者不修改生产输入。
- 补充范围不足、非法结构、只读无写入、越界、错偏移、对齐、生命周期、来源、fragment 与原子负测。
- native GCC 写入 harness 覆盖偏移 0/8/24。真实双 ISA 生产测试加强断言，检查实际报告中的读/写范围、完整 intent、访问方向和合同版本；保留四层、中央审计及轨迹篡改拒绝断言。

这些范围描述获批片段的访问义务，不是整个程序或物理页面权限。外围初始化、返回读取和后状态输出仍由私有真实对象、AST scope 与部署合同约束；不加入 asm 的读取效果。

仅改变 L3 consumer 及相关测试，无需因本次改动重建未变更的 Phase95 calibrated backend。新运行必须重新生成 producer manifest、profile、requirements 和合同；不能复用或手工修补 Phase97 的失败报告、receipt 或 hash。backend 本身仍须通过身份校验。

## 主机步骤 1：更新与构建

已激活 .venv-l2 后逐块执行，命令不使用 shell exit 或 set -e。非零时保留目录并先查日志。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase98-l3-store-range-consumption
git switch --track origin/phase98-l3-store-range-consumption
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10=/usr/bin/clang-10
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE98_ROOT="$(mktemp -d "$REPO/experiment/results/phase98-XXXXXX")"
hash -r
printf 'PHASE98_ROOT=%s\n' "$PHASE98_ROOT"
command -v clang
clang --version
ls -l "$RV2X86_L3_TRACE_BACKEND"
cmake --build build -j2 > "$PHASE98_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE98_ROOT/build.log"
```

Clang 应为 10；backend 文件必须存在；构建状态为 0 后进入下一步。

## 步骤 2：定向回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_route_applicability.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_l2_memory_object_observation.py \
  --junitxml="$PHASE98_ROOT/focused.xml" \
  > "$PHASE98_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$PHASE98_ROOT/focused.log"
```

应无失败。主机具备 native GCC 时这组测试不应因 GCC 缺失跳过。它验证范围消费与接入规则，不替代下一步真实双端生产。

## 步骤 3：真实重命名读写验收

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_memory_trace_production.py \
  --junitxml="$PHASE98_ROOT/production.xml" \
  > "$PHASE98_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 100 "$PHASE98_ROOT/production.log"
```

要求 **4 passed、0 skipped**。每项先完成 L0/L1/L2/L3、真实事件和中央审计，然后故意破坏临时轨迹确认拒绝。成功后的临时目录不再是未篡改正向证据。任意写入配置失败时先按下述方法看首个阻塞，不进入大规模实验。

集中读取当前 pytest 结果与失败阶段，避免打印庞大的嵌套 stdout：

```bash
python3 - <<'PY'
import json, os, re
from pathlib import Path
import xml.etree.ElementTree as ET
root=Path(os.environ['PHASE98_ROOT'])
for name in ('focused.xml','production.xml'):
    path=root/name
    print('\nREPORT:',path)
    if not path.is_file():
        print('missing');continue
    cases=list(ET.parse(path).getroot().iter('testcase'))
    print('tests:',len(cases))
    for tag in ('failure','error','skipped'):
        selected=[c for c in cases if c.find(tag) is not None]
        print(tag+':',len(selected))
        for c in selected:
            node=c.find(tag)
            print('TEST:',c.get('classname'),c.get('name'))
            text=(node.text or '')+'\n'+node.get('message','')
            paths=set(re.findall(r'/tmp/pytest-of-root/[^\s"\\]+/production',text))
            for directory in sorted(paths):
                status=Path(directory)/'run-status.json'
                print('statusPath:',status)
                if not status.is_file():continue
                data=json.loads(status.read_text())
                print('stage:',data.get('currentStage'),'blockers:',data.get('blockers'))
                for case in data.get('caseDiagnostics',[]):
                    print('CASE:',case.get('reportPath'),case.get('status'),case.get('reasonCodes'))
                    print('staging:',case.get('requirementStagingFailure'))
                    for attempt in case.get('attempts',[]):
                        for layer in attempt.get('layers',[]):
                            print('LAYER:',layer.get('level'),layer.get('status'))
                            if layer.get('status')!='verified':print(layer.get('detail'))
PY
```

## 步骤 4：原始输入正向验收

前三步成功后运行。每项创建独立目录，要求 productionAcceptanceComplete=true、blockers=[]、四层 verified、独立审计通过。

```bash
python3 -m riscv2x86_py.l3_cache_model \
  --output "$PHASE98_ROOT/cache-model.json" \
  --line-bytes 64 --set-count 16 --ways 4
MODEL_STATUS=$?
printf 'model_status=%s\n' "$MODEL_STATUS"
for SOURCE in \
  "$REPO"/experiment/generated-suite/case_000_*.c \
  "$REPO"/experiment/generated-suite/case_001_*.c \
  "$REPO"/experiment/generated-suite/case_004_*.c \
  "$REPO"/experiment/generated-suite/case_009_*.c
do
  CASE_NAME="$(basename "$SOURCE" .c)"
  python3 experiment/run_l3_memory_trace.py \
    --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_TRACE_BACKEND" \
    --cache-model "$PHASE98_ROOT/cache-model.json" \
    --output "$PHASE98_ROOT/original-$CASE_NAME" \
    > "$PHASE98_ROOT/original-$CASE_NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
done
```

模型生成非零时不要执行后续循环。案例编号仅选择测试输入，不参与生产实现决策。写入事件必须为 write，偏移和宽度匹配获批事实；对象后状态必须符合输入和真实写入。

## 步骤 5：兼容性、覆盖和最终回归

恢复此前实际有效的 controlled-system、controlled-time、local-sync 声明/backend/runner 配置，执行原 016/022/024/029 独立与组合兼容实验。不要把这些环境配置混入当前 memory-trace 路线。若要再检查 32 项 L3 覆盖，按 Phase97 文档逐输入运行，改用本轮新输出目录；不要求所有不适用的输入变为 verified。

```bash
python3 experiment/verify_route_contracts.py \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --clang10 /usr/lib/llvm-10/bin/clang \
  --output "$PHASE98_ROOT/regression-final" \
  --require-no-regression-skips \
  > "$PHASE98_ROOT/regression-driver.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 40 "$PHASE98_ROOT/regression-final/regression.log"
python3 -m json.tool "$PHASE98_ROOT/regression-final/run-status.json"
```

这里传 LLVM 目录的 Clang10，避免 regression runner 将 /usr/bin 下的 Clang6 放在 PATH 最前。缺少显式配置时的 skip 必须查明，不能填虚构环境消除跳过。没有 --suite 时，回归不代表执行了 32 项生产实验。

## 完成条件与限制

本轮完成需要纯写入 authority 被正确消费，并由主机真实实验确认后续部署、捕获、比较和中央审计全部闭合。有限采样不能当作任意输入的普遍证明。声称范围仍是 compiler asm 区域成功访存序列与选定的抽象 LRU 模型；物理缓存、计时、推测、并发及其它未实现 L3 路线不因此获得许可。通用 L2 常量观察等 Phase97 已说明的剩余能力也不在本轮冒充完成。

## 本轮开发验证记录

修订前，仅将写入夹具改为真实的空读取范围即可稳定复现拒绝（5 failed、13 passed）。修订后定向集 **163 passed**；选定回归 **1558 passed、47 skipped**。47 项跳过来自开发容器缺少真实 ISA 工具链或未选择显式 backend，不能算作主机无跳过验收。native GCC 的三个偏移写入 harness 均实际编译运行；真实双 ISA 四项生产测试仍是主机强制验收条件。

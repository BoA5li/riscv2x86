# Phase126：M0覆盖账本与M1中央证据闭包修订验收

基线为 Phase125 `31bdd8a38bc7ee0620af3a85636a061a6273bbc7`。
新分支 `phase126-m0-m1-evidence-closure`。保留旧 `phase125-Yh11ki` 失败目录，不改写历史结果。

本轮修复：

1. 联合L2缺失基础维度能力声明；统一从生产合同生成配置。
2. scalar要求两个维度、memory要求三个维度；拆分两个provider合同，共用同一真实观察实现，保留中央精确匹配检查。
3. 联合观察放入replayDirectory，返回相对引用；保留路径限制、不可覆盖发布和类型敏感重放。
4. scalar材料化不再把联合边界观察错误降级为缺失旧单一sink authority；新增绑定编译器作用域、依赖图、证明与操作数的静态合同，并由joint spec重放。静态合同不声称观察已发生。
5. 持久化重读重新核验原始执行记录、所有中间值与对象、样本计划、模板和独立重建的执行镜像；联合L3独立审计同时核验各成员的中央L2证据。
6. 新增12轴支持域账本和逐源文件覆盖清单；实际配置匹配、静态前提与运行/审计状态分离。

M0的plan schema升级为v2，旧ready改为candidate_available（joint为static_prerequisites_satisfied）。
保留complete字段供已有选路消费者读取，但其scope明确仅为静态候选/合同，不表示backend、执行或验收完成。
`l3_capability_assessment` v2仅在收到正式L2配置并成功解析后才标记configurationPrerequisitesComplete；
未提供配置为not_assessed。即使静态与配置条件满足，runtimeStages仍为not_run、semanticApproval=false、productionAcceptanceComplete=false。

生产验收前不能标记M1已完成；M2-M8未在本轮扩展。以下按块执行，某步失败则暂停依赖它的后续步骤。

## 实现范围与证据含义

- 编译器 AST 确认的一个导出入口、1–4 个参数、一个 unsigned64 指针对象，其余参数与返回值为 unsigned64。
- 2–16 个直接、无环 asm 区域；每个区域仍须有完整源语义、目标关系、外壳、操作数和依赖图证明。
- 支持域内的普通 64 位 load、scalar 和 store；同一对象可有多个访问与不同已证明偏移，必须同时含 load 和 store。每个访存 asm 目前仍限一个已证明访问。
- 局部标量必须由前序 asm 定义；不接受 C 初始化器、C 计算、调用、分支、循环或指针重绑定。返回已定义的直接声明载体。
- 统一的类型调用与对象样本计划，初始化一次对象后执行完整调用；区域之间不重置对象或参数。
- L2 使用明确标识的测试变体，在所有区域前后读取实际操作数和完整对象，核对数据流、读值、写值、对象连续性和返回值。测试变体不是 L3 机器码证据。
- L3 执行原函数代码：零字节区域标签后，逐字节检查函数代码与评估构建产物一致，链接后再次检查。两侧各执行一组完整调用，所有成员共享同一个捕获组。
- L3 比较每个访问的调用号、区域、方向、宽度和对象相对偏移，以及完整对象和返回值；检查批准写区间以外的字节未改变。
- 独立审计重新构建部署、解析原始执行与访存日志、重建结果，核对全部成员、性质、证明、执行绑定和共同捕获组。缺失成员、篡改原始轨迹、重复或不相关证据不能通过。
- 有限样本只支持声明的 `architectural_intent` 观察；不声称全部输入的动态穷尽证明，也不声称物理缓存、时序、推测或并发原子性实测。

## 代码位置

| 环节 | 文件 |
| --- | --- |
| 编译器类型、直接区域及调用范围 | `compiler_joint_scope.py`、`automatic_batch_cli.py` |
| 成员证明、对象与依赖闭包重放 | `l3_joint_spec.py`、`automatic_l2_authority.py` |
| L2 实际中间值、对象及调用观察 | `automatic_l2_joint.py`、`l3_joint_observation.py` |
| 真实后端校准、原机器码部署 | `l3_joint_backend.py`、`l3_joint_deployment.py` |
| 源义务与整体捕获、逐成员闭包 | `l3_joint_intent.py`、`l3_joint_route.py` |
| 选择、接入、整体独立审计 | `l3_mechanism_selection.py`、`l3_production_acceptance.py` |
| 正常生产驱动与验收 | `experiment/run_l3_joint_trace.py`、`test_l3_joint_production.py` |

文件位于 `pytools/riscv2x86_py/`，测试位于 `pytools/tests/`。旧路线默认约束保留；新调用需要显式选择 `joint` 后端。

## 1. 更新与环境

不要清理或覆盖本地 build、实验结果与其它改动；如果 switch 报冲突，保留完整信息先处理。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase126-m0-m1-evidence-closure
git switch --track origin/phase126-m0-m1-evidence-closure
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in /usr/lib/llvm-10/bin:*) ;; *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;; esac
hash -r
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE126_ROOT="$(mktemp -d "$REPO/experiment/results/phase126-XXXXXX")"
printf 'PHASE126_ROOT=%s\n' "$PHASE126_ROOT"
git rev-parse HEAD > "$PHASE126_ROOT/git-head.txt"
cmake --build build > "$PHASE126_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE126_ROOT/build.log"
```

构建必须为0。以下按块执行；任一步不符合预期时保留目录和日志，暂停依赖该结果的下一步。
不要重复使用已有输出目录，也不要手改 backend.json 的身份或文件摘要。

## 2. 定向测试与真实 AST

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_automatic_l2_authority.py \
  pytools/tests/test_automatic_l2_effect.py \
  pytools/tests/test_l3_capability_assessment.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  --junitxml="$PHASE126_ROOT/focused.xml" \
  > "$PHASE126_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE126_ROOT/focused.log"
```

要求状态0；`test_l3_joint_program.py` 中4项真实 Clang AST 测试必须执行，不能跳过。
本地开发环境通过原生执行、插件回调、反例检查；没有 RISC-V GCC/QEMU/Clang，未代替主机生产验收。

## 3. 新后端准备与8项校准

```bash
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE126_ROOT/joint-backend" \
  > "$PHASE126_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'joint_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE126_ROOT/joint-backend.log"
cat "$PHASE126_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$PHASE126_ROOT/joint-backend/backend.json"
```

要求状态0、complete=true、stage=complete、calibrationCompleted 数量8：source/target 分别执行 empty/read/write/skip。
skip 是负向校准，应证实遗漏区域被拒绝。semanticApproval=false 是正确的：后端准备不批准任何程序。
校准审计同时独立重建探针执行镜像。包实现改变后应重新准备该后端。

## 4. 保留原始证据的正常生产单例

```bash
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-load-add-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$PHASE126_ROOT/joint-smoke" \
  > "$PHASE126_ROOT/joint-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'joint_smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 80 "$PHASE126_ROOT/joint-smoke.log"
```

要求状态0。再独立读取结果，不能只凭进程返回值批准：

```bash
python3 - <<'PY' > "$PHASE126_ROOT/joint-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root=Path(os.environ['PHASE126_ROOT'])/'joint-smoke'
state=json.loads((root/'run-status.json').read_text())
for key in ('currentStage','executionComplete','independentResultAuditComplete','productionAcceptanceComplete','blockers'):
    print(key, state.get(key), flush=True)
paths=list(root.glob('batch/cases/*/evaluation-result.json'))
if len(paths)!=1: raise SystemExit('报告数量异常')
r=json.loads(paths[0].read_text()); print('evaluationStatus',r['status'])
groups=set()
for attempt in r['attempts']:
    print('fragment',attempt['fragmentId'])
    for layer in attempt['validation']['layers']: print(layer['level'],layer['status'])
    d=json.loads(attempt['validation']['layers'][3]['detail']); groups.add(d['jointCapturePath'])
print('attemptCount',len(r['attempts']),'captureGroupCount',len(groups))
print('AUDIT',json.dumps(audit_evaluation(r),ensure_ascii=False,indent=2),flush=True)
if (state.get('currentStage')!='complete' or state.get('blockers')
    or any(state.get(k) is not True for k in ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))
    or r['status']!='verified' or len(r['attempts'])!=3 or len(groups)!=1):
    raise SystemExit('工作链未闭环')
PY
AUDIT_STATUS=$?
printf 'joint_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE126_ROOT/joint-audit.log"
```

预期：三个成员都 L0–L3 verified，独立审计 verified，programExecutionUnitCount=1。
组内两侧各8次调用、16个访存事件；load偏移8、store偏移16、宽度8，中间scalar区域无访存。

## 5. 生产矩阵与反例

单例通过后执行完整矩阵，避免每个小改动都跑全部旧生产矩阵：

```bash
export MATRIX_ROOT="$(mktemp -d "$PHASE126_ROOT/joint-matrix-XXXXXX")"
python3 -m pytest -vv -rs pytools/tests/test_l3_joint_production.py \
  --basetemp="$MATRIX_ROOT/pytest" \
  --junitxml="$MATRIX_ROOT/production.xml" \
  > "$MATRIX_ROOT/production.log" 2>&1
MATRIX_STATUS=$?
printf 'joint_matrix_status=%s\n' "$MATRIX_STATUS"
tail -n 140 "$MATRIX_ROOT/production.log"
```

共12项：原8项 add/xor/and/or × 指针参数位置0/1，加4项已声明调用/区域边界：1参数/2区域、3参数/3区域、4参数/3区域、2参数/16区域。全部应通过且无跳过。
每项包含正常生产、共享捕获检查、缺失成员审计拒绝和原始写轨迹篡改审计拒绝。
测试尾部故意篡改临时负向证据，所以不要把 pytest 整棵目录作为全部正例重新审计；第4步单例保留未篡改证据。

失败时请提供 git-head.txt、focused.log、joint-backend.log/build-status.json、
对应 run-status.json、batch.log、evaluation-result.json 中未通过层的 detail 和 translation 命令 stderr。
无需粘贴所有成功对象、二进制内容或完整巨大快照。

## 6. 兼容检查与后续边界

本轮已有旧路线自动化相关回归；主机联合单例与12项生产通过后，再按既有步骤执行普通load/store生产兼容检查。
类型访存 wrapper 固定了包摘要，本轮代码改变后需用 `l3_memory_backend --include-loads` 重新准备 wrapper，
不能复用旧 typed wrapper 或仅替换摘要。兼容测试使用下列当前文件名与对应环境变量：

```bash
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" --include-loads \
  --output "$PHASE126_ROOT/typed-memory-backend" \
  > "$PHASE126_ROOT/typed-memory-backend.log" 2>&1
TYPED_STATUS=$?
printf 'typed_backend_status=%s\n' "$TYPED_STATUS"
tail -n 60 "$PHASE126_ROOT/typed-memory-backend.log"
```

仅在该步骤状态0且 build-status.json 为 complete 后继续：

```bash
export RV2X86_L3_TYPED_LOAD_BACKEND="$PHASE126_ROOT/typed-memory-backend/backend.json"
export RV2X86_L3_TYPED_MEMORY_BACKEND="$RV2X86_L3_TYPED_LOAD_BACKEND"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_typed_load_production.py \
  pytools/tests/test_l3_typed_store_production.py \
  --junitxml="$PHASE126_ROOT/compatibility.xml" \
  > "$PHASE126_ROOT/compatibility.log" 2>&1
COMPAT_STATUS=$?
printf 'compatibility_status=%s\n' "$COMPAT_STATUS"
tail -n 100 "$PHASE126_ROOT/compatibility.log"
```

用新的正常输出目录保存结果；不要求重新跑本次已经通过且代码未再改变的检查。

尚未完成：控制流/循环与访存联合、fence/atomic联合、跨对象与别名、联合域窄宽度与signed、
通用C表达式/调用、多出口、原子非零偏移与活跃LR/SC辅助输出，以及visibility/environment自动L3路线。
不能把本次bounded联合域通过称为这些能力已补齐。下一阶段应沿同一捕获与整体审计框架增加证明和真实观察，
每次扩展连同正例、反例、持久化重放和主机生产一起验收。

## M0账本验收

以下命令只读既有结果、生成新账本，不重跑翻译器、不修改原结果。

先核对32种子清单是否完整；未运行种子必须保留为not_run，不能从统计分母剔除：

```bash
python3 -m riscv2x86_py.l3_coverage_inventory \
  --sources "$REPO/experiment/generated-suite" \
  --results "$REPO/experiment/results/phase125-Yh11ki" \
  --clang "$RV2X86_SYSTEM_CLANG" --capability joint \
  --output "$PHASE126_ROOT/generated-seed-ledger.json" \
  > "$PHASE126_ROOT/generated-seed-ledger.log" 2>&1
LEDGER_STATUS=$?
printf 'seed_ledger_status=%s\n' "$LEDGER_STATUS"
cat "$PHASE126_ROOT/generated-seed-ledger.log"
```

预期sourceCount与实际源清单一致（当前应为32），没有运行报告的条目为not_run；
这不表示32个种子都已验证，也不表示它们均属于联合域。域成员资格只能由编译器与证明合同确认。
源检查成功不等于翻译证明完整。当前环境类、控制类等种子保留其未完成能力。

保留上一轮正常单例的历史阻塞（它的源文件在experiment/inputs下）：

```bash
python3 -m riscv2x86_py.l3_coverage_inventory \
  --sources "$REPO/experiment/inputs" \
  --results "$REPO/experiment/results/phase125-Yh11ki" \
  --capability joint \
  --output "$PHASE126_ROOT/previous-failure-ledger.json" \
  > "$PHASE126_ROOT/previous-failure-ledger.log" 2>&1
PREVIOUS_STATUS=$?
printf 'previous_ledger_status=%s\n' "$PREVIOUS_STATUS"
cat "$PHASE126_ROOT/previous-failure-ledger.log"
```

账本应保留L2 provider-resolution阻塞，而不是将下游审计未运行当作最早语义失败。
旧联合证据不具有本轮新增合同，不允许补写历史证明字段来使其通过。

在本轮生产单例完成后生成新账本：

```bash
python3 -m riscv2x86_py.l3_coverage_inventory \
  --sources "$REPO/experiment/inputs" \
  --results "$PHASE126_ROOT/joint-smoke" \
  --capability joint \
  --output "$PHASE126_ROOT/current-smoke-ledger.json" \
  > "$PHASE126_ROOT/current-smoke-ledger.log" 2>&1
CURRENT_STATUS=$?
printf 'current_ledger_status=%s\n' "$CURRENT_STATUS"
cat "$PHASE126_ROOT/current-smoke-ledger.log"
```

正常单例所属记录应为accepted，且每个正式registry配置的configurationPrerequisitesComplete=true。
其它未运行源文件仍为not_run。顶层semanticApproval和productionAcceptanceComplete始终false：
账本本身不批准程序；具体run的productionAcceptanceComplete只有独立审计成功才为true。
若有errors，保留具体错误；不能删除条目、忽略损坏证据后声称覆盖完成。

只输出必要摘要，避免上传完整巨型捕获：

```bash
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['PHASE126_ROOT'])
for name in ('generated-seed-ledger','previous-failure-ledger','current-smoke-ledger'):
    p=root/(name+'.json')
    if not p.is_file():
        print(name,'MISSING');continue
    v=json.loads(p.read_text());print(name,v['sourceCount'],v['statusCounts'],'errors:',v['errors'])
    for row in v['records']:
        if not row['runs']:continue
        print('SOURCE',row['sourcePath'],'membership',row['expectedDomainMembership'],'coverage',row['coverageStatus'])
        for run in row['runs']:
            print('RUN',run['recordedStages'],'firstBlocker',run['firstRecordedBlocker'],'accepted',run['productionAcceptanceComplete'])
            for c in run.get('recordedConfigurationAssessments',[]):
                a=c['assessment'];print('CONFIG',a['configurationAssessment']['status'],a['preExecutionPrerequisitesComplete'])
PY
```

旧新结果的sourceInventory可核对源摘要；catalog固定Phase124基线并记录实现摘要。
每条历史run均保留，不选择最后一次通过来隐藏先前失败；账本不是修改选路或放宽证明的入口。

## 开发端验证与主机完成条件

开发端有真实native gcc，缺少Clang、RISC-V GCC与QEMU。新增中央registry集成测试使用显式标注的native工具替身和证明/AST fixture，验证注册、中央闭包、持久化、重读及反例；不作为双ISA生产证据。

M0验收：完整源清单、12轴期望、独立静态/配置/运行阶段、保留历史失败，且缺配置/缺证据不产生虚假批准。
M1验收：正式生产单例、三个成员L0-L3、中央L2重放、共同L3捕获、独立审计、12项生产与旧load/store兼容均通过。
任何域内新阻塞都保留原始原因继续修复，不能通过改变域声明或跳过样例判定完成。

开发端最终相关回归：1852 passed、4 skipped、0 failure/error，76.05秒；跳过项仅为真实Clang检查。
新增中央registry、账本和相关驱动定向检查：85 passed。语法及文档bash块检查通过。
以上不包含主机双ISA生产矩阵；4项真实Clang检查和12项生产必须由主机执行，不能把native替身视为通过依据。

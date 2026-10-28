# Phase118：LR/SC 持久化合同严格重放

Phase117 宿主机的两个原始输入均已翻译 emitted，L0–L2 verified；
L3 在独立重放时发生 `L3_LRSC_SPEC_REPLAY_MISMATCH`。
已定位并复现：源序列 DTO 的两个顺序位字段导出为 tuple，JSON 读取后为 list，
独立重建再返回 tuple，因此同一规格在严格结构比较中不等。

本轮在导出边界明确生成 JSON 数组；内部不可变模型仍使用 tuple。
不删除顺序位，不跳过独立比较，不以摘要相同替代结构与语义核验。
JSON 编码、modelIdentity/specIdentity 的算法和字段未改变。

实现范围：

- `lrsc_source.py`：`lr_ordering_bits`、`sc_ordering_bits` 导出为列表。
- `l3_trace_support.py`：通用 JSON 原生类型检查与完整、类型敏感的结构比较。
  不自动转换 tuple/set/bytes/非字符串键，不接受非有限数、循环引用。
  bool/int 不混同。差异错误包含字段路径、类型、长度或值。
- `l3_lrsc_spec.py`：规格导出立即检查 JSON 边界，尽早拒绝将来的同类表示错误。
- `l3_lrsc_deployment.py`：部署写入前检查，读取后严格验证字段与输入覆盖；
  独立比较完整规格、样本计划、函数、机器机制、区域与执行映像，保留原有摘要和机器字节检查。
- `l3_lrsc_route.py`：重放部署、观察、比较及最终结果时进行类型敏感比较，
  LR/SC 错误阶段名称改为 `l3-lrsc-*`。
- `experiment/inspect_lrsc_persistence.py`：只读重建已保存合同的规格；
  不需要复用过期 backend，也不授予执行审计或生产验收。

以下使用 Bash 和 `set +e`。每步通过后再进入下一步。
不要覆盖 Phase117 结果或手工更改任何旧 manifest 摘要。

## 1. 更新、环境、构建

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase118-lrsc-persisted-contract-replay
git switch --track origin/phase118-lrsc-persisted-contract-replay
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
export CONTROL_BACKEND="$REPO/experiment/results/phase108-VWL1Ko/control-backend/backend.json"
export PHASE118_ROOT="$(mktemp -d "$REPO/experiment/results/phase118-XXXXXX")"
printf 'PHASE118_ROOT=%s\n' "$PHASE118_ROOT"
git rev-parse HEAD > "$PHASE118_ROOT/git-head.txt"

cmake --build build > "$PHASE118_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE118_ROOT/build.log"
```

要求版本与发布提交相同，build_status=0。若同名本地分支已存在，
用 `git switch phase118-lrsc-persisted-contract-replay` 后核对 HEAD。
记录本轮 PHASE118_ROOT；恢复会话时直接 export 该实际路径，不再 mktemp。

## 2. 针对性回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_lrsc_persistence.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_lrsc_source.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_production_acceptance.py \
  --junitxml="$PHASE118_ROOT/focused.xml" \
  > "$PHASE118_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$PHASE118_ROOT/focused.log"
```

要求零失败、零错误、零跳过。新增持久化测试包括：全部 16 种顺序位组合，
32/64 位、ADD/AND/OR/XOR、ADDW、操作数排列、真实原生 x86 部署及完整对象状态，
保存/读取后的完整部署和合同重放、重算摘要后的篡改拒绝。
双侧部署结构测试使用明确标注的编译器/ELF I/O fixture；真实 RISC-V/QEMU
验收仍须后续实验，不将 fixture 当作宿主机执行证据。

## 3. 先用 Phase117 已保存合同确认同一错误解除

这是快速只读核验，不需要先重新运行 68 项校准。

```bash
python3 experiment/inspect_lrsc_persistence.py \
  --root "$REPO/experiment/results/phase117-4OECAh/production-validation-vvcWgn" \
  > "$PHASE118_ROOT/persisted-spec-preflight.log" 2>&1
SPEC_STATUS=$?
printf 'persisted_spec_status=%s\n' "$SPEC_STATUS"
cat "$PHASE118_ROOT/persisted-spec-preflight.log"
```

要求退出码 0、两个合同均 specReplayComplete=true，汇总 contractCount=2、errors=[]。
`executionAudited=false`、`productionAcceptanceComplete=false`、`semanticApproval=false`
是预期输出，因为此工具只核查规格重建，不绕过旧 backend 固定依赖或授予完整验收。
失败时优先提供这份短日志；不要继续长矩阵。

## 4. 验证 control，重新生成 LR/SC 校准 backend

本轮改变了固定依赖，Phase117 LR/SC manifest 不能直接复用。

```bash
python3 - <<'PY' > "$PHASE118_ROOT/control-validation.log" 2>&1
import os
from riscv2x86_py.l3_control_backend import validate
value = validate(os.environ['CONTROL_BACKEND'])
print('control_backend_verified:', value['backendIdentity'])
PY
CONTROL_STATUS=$?
printf 'control_validation_status=%s\n' "$CONTROL_STATUS"
cat "$PHASE118_ROOT/control-validation.log"

if [ "$CONTROL_STATUS" -eq 0 ]; then
  python3 -m riscv2x86_py.l3_lrsc_backend \
    --control-backend "$CONTROL_BACKEND" \
    --output "$PHASE118_ROOT/lrsc-backend" \
    > "$PHASE118_ROOT/lrsc-backend.log" 2>&1
  BACKEND_STATUS=$?
  printf 'lrsc_backend_status=%s\n' "$BACKEND_STATUS"
  tail -n 80 "$PHASE118_ROOT/lrsc-backend.log"
else
  printf 'control 验证失败，先核查日志，未启动校准。\n'
fi

python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['PHASE118_ROOT']) / 'lrsc-backend'
path = root / 'build-status.json'
if path.is_file():
    data = json.loads(path.read_text())
    for key in ('stage', 'complete', 'semanticApproval', 'error'):
        print(key + ':', data.get(key))
    print('calibrationCompleted:', len(data.get('calibrationCompleted', [])))
    print('backendManifestPresent:', (root / 'backend.json').is_file())
else:
    print('状态文件不存在，请核查校准日志。')
PY
```

要求 backend_status=0、stage=complete、complete=true、68 项完成、manifest 存在。
semanticApproval=false 正常。依赖验证失败时按具体过期文件新建依赖，不能改旧摘要。

## 5. 两个原始输入完成真实 L0–L3

```bash
export RV2X86_L3_LRSC_BACKEND="$PHASE118_ROOT/lrsc-backend/backend.json"
printf 'caseId\texitCode\n' > "$PHASE118_ROOT/exit-status.tsv"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 experiment/run_l3_lrsc_trace.py \
    --input "$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_LRSC_BACKEND" \
    --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --output "$PHASE118_ROOT/$NAME" \
    > "$PHASE118_ROOT/$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s\t%s\n' "$NAME" "$CASE_STATUS" >> "$PHASE118_ROOT/exit-status.tsv"
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done
python3 experiment/inspect_lrsc_evaluation.py --root "$PHASE118_ROOT" \
  > "$PHASE118_ROOT/evaluation-summary.txt" 2>&1
cat "$PHASE118_ROOT/exit-status.tsv"
cat "$PHASE118_ROOT/evaluation-summary.txt"
```

要求两个退出码均 0，翻译 emitted，L0–L3 verified。
再用通用独立验收入口重放：

```bash
python3 - <<'PY' > "$PHASE118_ROOT/acceptance-audit.log" 2>&1
import json
import os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE118_ROOT'])
failures = []
for name in ('lrsc_add_32', 'lrsc_add_64'):
    print('\nCASE:', name, flush=True)
    try:
        directory = root / name
        state = json.loads((directory / 'run-status.json').read_text())
        keys = ('executionComplete', 'independentResultAuditComplete', 'productionAcceptanceComplete')
        for key in ('currentStage', *keys, 'blockers', 'upstreamFailures'):
            if key in state:
                print(key + ':', state[key], flush=True)
        if state.get('currentStage') != 'complete' or state.get('blockers') or any(state.get(k) is not True for k in keys):
            raise ValueError('production completion checks failed')
        paths = list(directory.glob('batch/cases/*/evaluation-result.json'))
        if len(paths) != 1:
            raise ValueError('expected one evaluation report')
        report = json.loads(paths[0].read_text())
        for attempt in report.get('attempts', []):
            print('translationOutcome:', attempt.get('translationOutcome'))
            for layer in (attempt.get('validation') or {}).get('layers', []):
                print('LAYER:', layer.get('level'), layer.get('status'))
        result = audit_evaluation(report)
        print('INDEPENDENT_AUDIT:', json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        if report.get('status') != 'verified' or result.get('status') != 'verified':
            raise ValueError('evaluation or independent audit not verified')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        message = name + ': ' + type(exc).__name__ + ': ' + str(exc)
        failures.append(message)
        print('ERROR:', message, flush=True)
print('\nFAILURES:', failures, flush=True)
if failures:
    raise SystemExit(1)
PY
AUDIT_STATUS=$?
printf 'acceptance_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE118_ROOT/acceptance-audit.log"
```

要求所有完成标志 true、blockers=[]、独立审计 verified，control/memory/synchronization
三维均 verified。若失败，提供 evaluation-summary.txt、两个 run-status.json 与日志。
本轮差异错误会给出具体 JSON 字段路径，无需先导出几万行完整报告。

## 6. 原始输入通过后运行九项生产矩阵

```bash
python3 -m pytest -vv -rs pytools/tests/test_l3_lrsc_production.py \
  --junitxml="$PHASE118_ROOT/lrsc-production.xml" \
  > "$PHASE118_ROOT/lrsc-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'lrsc_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 120 "$PHASE118_ROOT/lrsc-production.log"
```

要求 9 passed，无失败、错误或跳过。生产测试包含修改层状态和原始轨迹的审计拒绝检查。
完成后再推进其它机制组合兼容性；共享 trace_support 的固定摘要已变，
旧 AMO/fence backend 要在新目录重新准备，不要沿用过期机制选择配置。
仍不声称已测量物理内存序、并发线性化、公平性或无界重试进展。

## 开发环境验证记录

修订前，完整批准规格的保存/读取回归实际失败，复现 tuple/list 差异。
修订后：新增测试集 178 passed；较广相关回归 1252 passed，
均无 failure/error/skipped。两轮范围存在重叠，不相加计数。
其中 178 项包含最后补充的只读工具测试。
开发环境只有原生 GCC；没有把真实 RISC-V/QEMU 校准或生产矩阵计为已通过。

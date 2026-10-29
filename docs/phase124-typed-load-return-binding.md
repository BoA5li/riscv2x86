# Phase124：编译器返回表达式与类型化 load 完整观察

本轮基于 Phase123，修复普通 load 的 32 位 GNU 输出经 C 整数转换返回 64 位结果时，
`returnDeclarationId` 为空而导致 `L3_MEMORY_LOAD_VALUE_BINDING_INVALID` 的接口缺口。
不改变 `_decl_identity()`、内存访问证明或输出载体关系；不按用例名称/指令文本放行。

## 实现及支持范围

* 新增 `compiler_return_binding.py`：复用类型化编译器表达式 DTO，保存源 digest、函数、
  返回语句范围、表达式与结果类型，声明叶子与逐级转换都保留。
* `automatic_batch_cli` 将事实放在 `l2OperandBoundary.compilerReturnBinding`。
  数值转换仍不填成旧 `returnDeclarationId`；导出事实不代表语义批准。
* load-call v2 携带完整返回表达式。`bind_load` 绑定叶子输出声明、类型、符号性、
  函数及内存证明；`validate_load_call`、实际返回比较和 JSON 重放使用同一严格合同。
* 仅接受整数声明、保持类型的包装及有定义且保留全部输出信息的整数转换链。
  禁止任何中间窄化，以及目标 signed 类型不能表示前一类型整个域的转换。
  unsigned 模转换逐步执行；例如 int32→uint32→uint64 不会被简化成 int32→uint64。
  算术、布尔、指针、一般返回表达式仍需另行证明，不能因最终返回宽而跳过中间过程。
* 旧 load-call v1 继续支持直接同宽、同符号性的返回；旧签名本身不能授权类型转换。
* 外层 experiment v6、deployment v3、observation v4 字段结构不变，内部版本化 call
  的 identity 纳入现有部署与实验绑定。解析器显式识别 v1/v2；部署重建通过
  `function_scope` 重新绑定编译器 snapshot，独立审计仍执行已有重放/文件/捕获检查。
* backend 按整个 Python 包固定实现，自动覆盖新增模块。因此必须重新准备 wrapper，
  不应修改旧 backend.json 的 identity 或文件 hash。底层 QEMU base backend 可复用。

现有单指针、单访问、对象范围、对齐、外壳、精确代码绑定、真实内存事件及完整对象
观察均保留。多访问/混合机制/一般调用图不在本轮新增支持范围。

## 验证边界

本地有 native C 编译器，没有 Clang、RISC-V GCC、双端 QEMU。新增本地检查覆盖 AST
结构→边界导出→load-call v2→native harness/对象/完整返回比较、严格 JSON 往返及反例。
它们不是双 ISA 生产验收。新增独立 6 项真实 Clang 接入测试，及既有 18 项真实 load
生产矩阵，均需在实验主机执行。下列步骤全部用 set +e，不关闭交互 shell；失败后保留
日志，不继续长矩阵。新目录避免覆盖已存在产物。

本地验证记录：跨路线回归 1,751 passed；最终定向检查 255 passed；均无失败、错误、跳过。
6 项真实 Clang 和 18 项双端生产共 24 项已收集，未在本地执行。Python 与文档 shell
语法、git diff --check 均通过。

## 1. 更新、构建、定向测试

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase124-typed-load-return-binding
git switch --track origin/phase124-typed-load-return-binding
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE124_ROOT="$(mktemp -d "$REPO/experiment/results/phase124-XXXXXX")"
hash -r
printf 'PHASE124_ROOT=%s\n' "$PHASE124_ROOT"
git rev-parse HEAD > "$PHASE124_ROOT/git-head.txt"
cmake --build build > "$PHASE124_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE124_ROOT/build.log"
```

构建返回 0 后：

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_compiler_return_binding.py \
  pytools/tests/test_typed_load_execution.py \
  pytools/tests/test_typed_load_backend.py \
  pytools/tests/test_l3_entry_binding.py \
  pytools/tests/test_l3_capability_assessment.py \
  pytools/tests/test_l3_scalar_trace.py \
  pytools/tests/test_l3_scalar_call.py \
  pytools/tests/test_l3_typed_memory.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_compiler_return_binding_clang.py \
  --junitxml="$PHASE124_ROOT/focused.xml" \
  > "$PHASE124_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$PHASE124_ROOT/focused.log"
```

当前清单预期 261 passed（255 本地可运行 + 6 真实 Clang 接入），不能有跳过。
6 项直接调用真实 inspect_entry_points，检查 8/16/32 signed/unsigned 输出扩宽到64，
并将真实 AST 导出的返回关系接入 load-call。其 finding 载体是测试 fixture，不是生产批准。

## 2. 准备新 wrapper

```bash
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json" \
  --include-loads \
  --output "$PHASE124_ROOT/typed-memory-backend" \
  > "$PHASE124_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE124_ROOT/backend.log"
if [ -f "$PHASE124_ROOT/typed-memory-backend/build-status.json" ]; then
  cat "$PHASE124_ROOT/typed-memory-backend/build-status.json"
fi
```

要求返回0、complete true、16个探针完成。semanticApproval false 正确。
成功后：

```bash
export RV2X86_L3_TYPED_LOAD_BACKEND="$PHASE124_ROOT/typed-memory-backend/backend.json"
export RV2X86_L3_TYPED_MEMORY_BACKEND="$RV2X86_L3_TYPED_LOAD_BACKEND"
```

## 3. 优先重测两个原失败参数

```bash
export TARGETED_ROOT="$(mktemp -d "$PHASE124_ROOT/targeted-XXXXXX")"
printf 'TARGETED_ROOT=%s\n' "$TARGETED_ROOT"
python3 -m pytest -vv -rs \
  'pytools/tests/test_l3_typed_load_production.py::test_real_typed_load_and_audit[32-zx-True-32-False]' \
  'pytools/tests/test_l3_typed_load_production.py::test_real_typed_load_and_audit[32-zx-False-32-False]' \
  --basetemp="$TARGETED_ROOT/pytest" \
  --junitxml="$TARGETED_ROOT/production.xml" \
  > "$TARGETED_ROOT/production.log" 2>&1
TARGETED_STATUS=$?
printf 'targeted_status=%s\n' "$TARGETED_STATUS"
tail -n 140 "$TARGETED_ROOT/production.log"
```

要求2 passed，无跳过。每项包含真实L0–L3和独立审计，再故意修改raw trace确认拒绝。
所以 pytest 目录不是全正例归档，不应在篡改后把该目录再次批量当正例审计。
若失败，不跑全矩阵，读取该用例 evaluation-result.json、commands、层detail与
compiler-candidates.json 的 compilerReturnBinding。不能在失败后手工补写 binding。

## 4. 完整生产和旧 store 回归

```bash
export LOAD_MATRIX_ROOT="$(mktemp -d "$PHASE124_ROOT/load-matrix-XXXXXX")"
printf 'LOAD_MATRIX_ROOT=%s\n' "$LOAD_MATRIX_ROOT"
python3 -m pytest -vv -rs pytools/tests/test_l3_typed_load_production.py \
  --basetemp="$LOAD_MATRIX_ROOT/pytest" \
  --junitxml="$LOAD_MATRIX_ROOT/production.xml" \
  > "$LOAD_MATRIX_ROOT/production.log" 2>&1
LOAD_STATUS=$?
printf 'load_matrix_status=%s\n' "$LOAD_STATUS"
tail -n 140 "$LOAD_MATRIX_ROOT/production.log"
```

要求18 passed，无跳过。成功后：

```bash
export STORE_MATRIX_ROOT="$(mktemp -d "$PHASE124_ROOT/store-compatibility-XXXXXX")"
printf 'STORE_MATRIX_ROOT=%s\n' "$STORE_MATRIX_ROOT"
python3 -m pytest -vv -rs pytools/tests/test_l3_typed_store_production.py \
  --basetemp="$STORE_MATRIX_ROOT/pytest" \
  --junitxml="$STORE_MATRIX_ROOT/production.xml" \
  > "$STORE_MATRIX_ROOT/production.log" 2>&1
STORE_STATUS=$?
printf 'store_matrix_status=%s\n' "$STORE_STATUS"
tail -n 120 "$STORE_MATRIX_ROOT/production.log"
```

要求17 passed。不要删除原失败参数来凑齐通过数。需保留三个生产阶段的JUnit和日志。

```bash
python3 - <<'PY'
import os
from pathlib import Path
import xml.etree.ElementTree as ET
failures=[]
for variable, filename, expected in (
    ('PHASE124_ROOT','focused.xml',261),
    ('TARGETED_ROOT','production.xml',2),
    ('LOAD_MATRIX_ROOT','production.xml',18),
    ('STORE_MATRIX_ROOT','production.xml',17),
):
    root=os.environ.get(variable)
    path=Path(root)/filename if root else None
    print('\nREPORT:',variable,path)
    if path is None or not path.is_file():
        failures.append(variable+': missing report');continue
    cases=list(ET.parse(path).getroot().iter('testcase'))
    print('tests:',len(cases))
    if len(cases)!=expected:failures.append(variable+': unexpected count')
    for tag in ('failure','error','skipped'):
        matches=[c for c in cases if c.find(tag) is not None]
        print(tag+':',len(matches))
        for case in matches:
            detail=case.find(tag)
            print(case.get('name'),detail.get('message') or detail.text or '')
        if matches:failures.append(variable+': '+tag)
print('\nFAILURES:',failures)
if failures:raise SystemExit(1)
PY
SUMMARY_STATUS=$?
printf 'summary_status=%s\n' "$SUMMARY_STATUS"
```

当前两个缺口的完成标准是：真实返回关系导出正确，内存证明仍为32位identity，
实际高位按C类型转换分别观察正确，所有层及独立审计通过，反例必须拒绝，旧路线无回归。
单元测试通过或backend校准完成不能替代以上生产验收。

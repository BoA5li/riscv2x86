# Phase136：编译器原子调用合同与 control 入口绑定

基线：Phase135 `696b05b00bc0d3c8badbf6971a6105e74b6a2a4b`。
分支：`phase136-atomic-call-contracts`。

**本轮没有完成全部 M4/M5。它只交付可单独验收的调用基础子域；不能把它标记为完整阶段交付。**

## 实际改动

1. 新增 `atomic_call_contract.bind()`，消费编译器导出的 LP64 类型合同，绑定声明、参数角色、宽度、入口及源身份。
   在原两参数路线之外，新增三/四参数、一个 unsigned 32/64 位对象指针、unsigned 32/64 位整数的调用。
   指针和 RMW 输入可处在不同位置；其它参数仍受原 sole-asm 外壳和完整用途证明约束。
   这不是一般 C 表达式、signed 接口或多指针支持。
2. L2 harness 调用真实原函数，记录所有整数实参，并与声明的边界计划核对，保留返回值和全部对象字节比较。
   LR/SC 的 old/next/status 返回语义、完整高位比较和失败尝试观察边界不变。
3. 新调用使用 atomic spec v3、sample plan v2；旧两参数路径不添加新字段，保留其原 harness 和样本表示。
   新计划保留旧值/RMW 输入的边界笛卡尔积，辅助参数采用声明的轮换边界向量；不声称穷尽所有参数组合。
4. 新 L3 harness 用真实类型变量传入每个参数，序列化全部实参；指针值与实际 objectBase 关联，各 ISA 不比较绝对地址。
   规格、计划、生成器和所有实参都进入已有部署重建和独立重放，不信任记录里的 verified 标志。
5. x86 CAS 符号状态增加第 3/4 个寄存器参数身份；不再只初始化前两个参数。
   RISC-V 现有四参数状态继续使用，目标重试不变式和完整返回核验均保留。
6. atomic/LRSC 部署重建额外比较 compilerMemoryCallSignature。
7. control 部署按 functionId 选择唯一入口，不再因存在未调用的无关函数直接拒绝。
   不支持可达 callee；scope、原始重写、ABI、机器图、路径和实际 transfer-shape 要求保持。

所有新文件自动纳入现有实现摘要。新调用的类型合同只是事实，不是语义批准；现有证明、侧车、L2 和 L3 门槛继续生效。
没有删除地址零偏移限制，没有增加未经证明的操作族，没有允许任意循环或减少审计。
没有为了测试通过自动更改源函数签名、插入 fake register observation 或扩张原子回调。
本轮没有性能策略修改，也没有新加速结论。

## 仍未实现的 M4/M5 项目

| 范围 | 状态 |
| --- | --- |
| 一般调用 | 本轮仅推进到三/四参数、单 unsigned 对象和 unsigned 32/64 参数；更广类型、返回转换和多指针仍未完成 |
| 原子地址 | 非零偏移和一般地址表达式仍未完成；原有拒绝门槛保留 |
| 多个活跃输出 | 仍只支持一个直接返回输出；输出参数、聚合返回和其它消费尚未完成 |
| 新原子操作族 | 仍为直接五类、LR/SC 四类 ALU；未扩大白名单 |
| 混合原子上下文 | execution plan/joint spec/比较/整体审计尚未接通 |
| 控制与真实对象 | control spec 和 machine 仍不支持一般对象访问 |
| CFG、合流和多出口 | 编译器一般 CFG、数据/内存合流和完整动态闭包仍未建立 |
| 有界循环 | 不变式、边界证明和动态迭代观察仍未实现；预算不视为证明 |
| 动态协议 | program plugin 仍为原固定顺序协议；未删除 next_region 检查 |
| 整体审计 | atomic/LRSC/control 仍有独立单片段限制 |

这些项目不会通过当前新测试自动结清。剩余实施需要继续建立共享区域图、对象状态、动态协议及对应证明；没有把缺口改成完成状态。

## 本地验证记录

- 扩大相关回归：909 passed，86.12 秒。
- 最终调用专项：24 passed，5.54 秒；与上述范围重叠，不相加。
- 新增生产与既有生产测试：共 63 项因未选择真实校准后端而 skipped，不能记为通过。
- 修改的 Python 文件通过 Python 3.10 AST 语法检查，git diff --check 无错误。
- 本地没有真实 Clang10/RISC-V GCC/QEMU 生产环境，尚无本轮双 ISA 验收或加速数据。

## 验证方法

如果 Phase135 的生产矩阵仍在执行，先完成并归档，不要在运行中切换实现文件；后端摘要变化会正确导致拒绝。

以下在 Bash、已激活 `.venv-l2` 下逐步执行。每组退出码为 0 后再继续，失败时保存日志。

### 1. 更新与环境

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase136-atomic-call-contracts
git switch --track origin/phase136-atomic-call-contracts
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase136-XXXXXX")"
hash -r
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

同名分支已存在时使用 git switch 后 git merge --ff-only 对应 origin 分支。
不清除本地 build 修改；本轮未改变 C++ 前端实现。

### 2. 快速回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_atomic_call_contract.py \
  pytools/tests/test_lrsc_live_return.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_l3_lrsc_persistence.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_control_machine.py \
  pytools/tests/test_l3_control_spec.py \
  pytools/tests/test_l3_atomic_retry.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$CHECK_ROOT/focused.log"
```

本地测试包含原生 x86 执行、GCC 最终机器码检查、RISC-V 字节 fixture、类型/角色/摘要/实参篡改拒绝。
不能将这些 native/fixture 结果称为真实双 ISA 生产验收。

### 3. 新建 wrapper

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_control_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/control-backend" > "$CHECK_ROOT/control-backend.log" 2>&1
CONTROL_STATUS=$?
printf 'control_backend_status=%s\n' "$CONTROL_STATUS"
tail -n 40 "$CHECK_ROOT/control-backend.log"
export RV2X86_L3_CONTROL_BACKEND="$CHECK_ROOT/control-backend/backend.json"
```

control 成功后分别准备 atomic 和 LRSC；底层 QEMU 可复用，不手改旧 wrapper 摘要。

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$RV2X86_L3_CONTROL_BACKEND" \
  --output "$CHECK_ROOT/atomic-backend" > "$CHECK_ROOT/atomic-backend.log" 2>&1
ATOMIC_BACKEND_STATUS=$?
printf 'atomic_backend_status=%s\n' "$ATOMIC_BACKEND_STATUS"
tail -n 40 "$CHECK_ROOT/atomic-backend.log"
export RV2X86_L3_ATOMIC_BACKEND="$CHECK_ROOT/atomic-backend/backend.json"
```

```bash
python3 -m riscv2x86_py.l3_lrsc_backend \
  --control-backend "$RV2X86_L3_CONTROL_BACKEND" \
  --output "$CHECK_ROOT/lrsc-backend" > "$CHECK_ROOT/lrsc-backend.log" 2>&1
LRSC_BACKEND_STATUS=$?
printf 'lrsc_backend_status=%s\n' "$LRSC_BACKEND_STATUS"
tail -n 40 "$CHECK_ROOT/lrsc-backend.log"
export RV2X86_L3_LRSC_BACKEND="$CHECK_ROOT/lrsc-backend/backend.json"
```

要求校准完整、stage=complete、complete=true；semanticApproval=false 正常。

### 4. 新增生产验收，分三组避免重复长跑

```bash
export TIMEFORMAT=$'wall_seconds=%R\nuser_seconds=%U\nsystem_seconds=%S'
for KIND in atomic lrsc control
do
  case "$KIND" in
    atomic) FILTER="test_extended_atomic_call" ;;
    lrsc) FILTER="test_extended_lrsc_call" ;;
    control) FILTER="test_control_entry_with_unrelated_function" ;;
  esac
  {
    time python3 -m pytest -vv -rs --durations=0 \
      pytools/tests/test_l3_extended_call_production.py -k "$FILTER" \
      --basetemp="$CHECK_ROOT/$KIND-pytest" \
      --junitxml="$CHECK_ROOT/$KIND-production.xml" \
      > "$CHECK_ROOT/$KIND-production.log" 2>&1
  } 2> "$CHECK_ROOT/$KIND-resource.txt"
  CASE_STATUS=$?
  printf '%s_status=%s\n' "$KIND" "$CASE_STATUS"
  tail -n 70 "$CHECK_ROOT/$KIND-production.log"
  cat "$CHECK_ROOT/$KIND-resource.txt"
  if [ "$CASE_STATUS" -ne 0 ]; then
    printf '本组失败，停止后续生产组，请保留日志。\n'
    break
  fi
done
```

每组要求 4 passed、8 deselected、无 skipped，合计 12 个不同测试。
每项仍含普通生产、L0--L3、独立审计和负例。

### 5. 既有功能回归

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_atomic_production.py \
  pytools/tests/test_l3_lrsc_production.py \
  pytools/tests/test_l3_lrsc_live_production.py \
  pytools/tests/test_l3_control_production.py \
  --basetemp="$CHECK_ROOT/compat-pytest" \
  --junitxml="$CHECK_ROOT/compat.xml" \
  > "$CHECK_ROOT/compat.log" 2>&1
COMPAT_STATUS=$?
printf 'compat_status=%s\n' "$COMPAT_STATUS"
tail -n 110 "$CHECK_ROOT/compat.log"
```

预期 51 passed、无 skipped：18 直接原子、27 LRSC、6 control。
Phase135 已完成的结果仍归档在原目录，不用新代码回写其摘要。
本轮 package 摘要变化后，若运行 joint 回归，也须生成新 joint wrapper。

以上通过只能验收本轮子域，不能声称完整 M4/M5 已完成。

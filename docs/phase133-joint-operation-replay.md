# Phase133：按评估边界复用重放，关闭前独立重验

基线：Phase132 `8f20c3f68f0c5f88cc577e206704d1c5b2c1f8a8`。
分支：`phase133-joint-operation-replay`。

## 目的与边界

这一轮修订针对已经测到的 joint 路线性能瓶颈，不改变语义域、样本计划、别名布局、证明要求、L0–L3、机器事件或独立审计的通过条件。
完整 M2/M3 的语义覆盖仍未全部完成：单 asm 多访存效应、一般地址/值表达式和其它 fence 域等仍须另行补齐。
这里的“完成性能修订”仅指已定位的重复工作，不代表穷尽所有潜在性能问题。

用户提供的 Phase132 计时表明：smoke 的基础后端检查有 53 次、累计约 266 秒；独立审计有 9 次、累计约 43 秒。
L2 独立重放在 smoke 中有 20 次、累计约 111 秒；真实双侧 capture 累计约 0.43 秒。
跨进程 inclusive/exclusive 计时不能相加当作端到端墙钟，也不能据此推断精确加速比。

## 修订

1. `joint_validation_operation` 为一次 `run_evaluation` 和每次独立 joint audit 分别建立私有作用域。
   仅成功结果可复用，输入必须是 JSON 原生值；键包括完整输入、路径及内容摘要。返回深拷贝，布尔值与整数保持区别。
   作用域不跨评估、审计、进程或线程，不写持久化信任缓存。
2. joint-only mechanism selection、joint 后端完整校验及整程序意图 producer replay，在同一作用域内按相同输入复用。
   每个 receipt 仍检查当前 manifest、工具绑定、成员身份、批准关系、profile、receipt 和 disposition。
   producer 的完整输出只共享一次计算，不共享“该成员已通过”的判断。
3. L2 independent replay 将共同的编译器/证明重建、instrumented source/target 编译和 ELF image 重建移至整程序计算。
   每个成员仍重查自身文件、approved relation authority、命令参数、原始 stdout、执行状态、边界值、对象值、计划和最终比较。
   初次 L2 观察仍按原逻辑实际执行；没有用 L3 观察替代 L2 依据。
4. 正常返回之前，对作用域中所有共享计算重新调用原始完整检查器，关闭所有本轮复用，再作类型敏感结构比较。
   所有被观察文件也必须保持初始摘要。独立审计创建新作用域并再次完成此关闭过程，不消费生产阶段的信任。
   关闭重验失败时不返回成功；普通 batch 入口保留结构化 orchestration failure。
   已暂存的 capture/层记录不等于最终生产验收，最终状态和独立审计仍是必需条件。
5. `RV2X86_JOINT_OPERATION_REUSE=0` 关闭本轮复用，用同版本完整重复工作作 A/B 对照；默认值 `1`。
   非法值报错。此开关不关闭 Phase131 的原有 capture-local session，也不改变语义检查。
6. 新增 `joint.backend-full-validation`、`joint.mechanism-selection-full-validation`、
   `joint.intent-program-replay`、`joint.l2-program-full-rebuild` 和 `joint.operation-closing-replay` 计时。
   `joint.backend-validation` 是 API 请求次数，不能再把它直接当作真正完整校验次数。
   capture 内可能只看到首次完整校验；强制关闭校验属于外层 evaluation/audit，不能要求 capture 子树固定出现 24 次 calibration。

复用要求输入在一次操作期间稳定；文件在任一检查点变化会拒绝。此机制不声称解决任意并发对抗性文件替换问题。
没有修改 Phase95 基础后端的固定实现文件；新的 joint wrapper 必须重建，因为它固定了本轮 Python 实现摘要。

## 本地验证记录

扩大 joint、对象布局、编译器快照、ingress、protocol、backend、L2 registry 和 evaluation 回归：**328 passed、4 skipped**（4 项缺少真实 Clang）。
补充操作生命周期/A-B 诊断及 batch 入口检查：**35 passed、30 skipped**（30 项需要真实校准双 ISA 后端）。两次测试范围重叠，数量不相加。
关闭本轮复用（`RV2X86_JOINT_OPERATION_REUSE=0`）的既有 capture/ingress/L2/evaluation 回归：**76 passed**；最终新增生命周期/A-B 检查：**24 passed**。这些范围也有重叠，不合并计数。
本地无法运行用户主机上的真实 RISC-V/QEMU 工具链，因此尚未宣称生产矩阵通过或取得真实加速比。

## 主机验证

以下命令用于 Bash，每块单独粘贴；不需要新的多行 Python here-document。
不复用旧输出目录，不删除旧实验；保持现有虚拟环境。预期外返回只记录，不关闭终端。

### 1. 更新与环境

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase133-joint-operation-replay
git switch --track origin/phase133-joint-operation-replay
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
case "$PATH" in /usr/lib/llvm-10/bin:*) ;; *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;; esac
hash -r
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase133-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

如果该本地分支已经存在，使用 `git switch phase133-joint-operation-replay`，随后 `git merge --ff-only origin/phase133-joint-operation-replay`。
本轮只改 Python、实验入口、测试和文档。已通过 Phase132 的同一前端可以继续使用；不要恢复/删除本地 build 文件。

### 2. 低成本功能和攻击性回归

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_joint_operation_replay.py \
  pytools/tests/test_joint_performance_comparison.py \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_evaluation_runner.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 70 "$CHECK_ROOT/focused.log"
```

新增测试核验：成功项复用和关闭重验、不同输入不混用、修改返回副本不污染共享值、类型敏感差异、失败不缓存、文件变化拒绝、嵌套独立审计不继承生产信任、真实原生编译的三个成员共享重建但逐成员关系/输出篡改仍拒绝、真实 producer 子进程的 receipt 批量重放。
原生与协议 fixture 不构成真实双 ISA 生产验收。

### 3. 重建 joint 后端

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" > "$CHECK_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'joint_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 60 "$CHECK_ROOT/joint-backend.log"
cat "$CHECK_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
export RV2X86_JOINT_OPERATION_REUSE=1
```

要求准备返回 0、`complete:true`；`semanticApproval:false` 正常，校准不是程序语义批准。
准备失败先核查日志，不启动后面的长矩阵。

### 4. 同版本同负载 A/B 生产与独立审计

```bash
python3 experiment/run_joint_performance_comparison.py \
  --input "$REPO/experiment/inputs/l3-joint-load-add-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/ab-smoke" --repeats 1 \
  > "$CHECK_ROOT/ab-smoke.log" 2>&1
AB_STATUS=$?
printf 'ab_status=%s\n' "$AB_STATUS"
cat "$CHECK_ROOT/ab-smoke/comparison.json"
```

入口分别以复用 0/1 执行全新生产工作链，再各启动一个新进程作 standalone audit；分别记录两类墙钟。
每次都要求完整状态、全部成员 L0–L3 verified、唯一 capture、独立审计通过。
对照还比较输入布局/参数、成员数、返回/对象值及事件形状；调用 nonce、绝对地址、PC 和运行生成路径的独立正确性由各自原始完整审计负责。
A/B 的规范化比较只作性能负载一致性诊断，不取代原始证据的语义审计。

`comparison.json` 要求 `complete:true`、每项 `accepted:true`、两个模式的样本/事件数相同。
`semanticApproval:false` 是性能汇总自身不授予批准，不能当作失败。
读取 `medians.production`、`medians.standaloneAudit` 中的秒数和加速比；单次值只用于工程诊断。
如果速度未改善也要保留结果，不设置“必须加速”来修改语义结果。

按每次运行分别汇总计时，例如：

```bash
for MODE in 0 1
do
  RUN_ROOT="$CHECK_ROOT/ab-smoke/repeat-0-reuse-$MODE"
  for KIND in production audit
  do
    python3 experiment/inspect_validation_timing.py \
      --input "$RUN_ROOT/$KIND-timing.jsonl" \
      > "$RUN_ROOT/$KIND-timing-summary.json"
    TIMING_STATUS=$?
    printf 'reuse=%s kind=%s timing_status=%s\n' "$MODE" "$KIND" "$TIMING_STATUS"
  done
done
```

对比完整校验/producer/L2 重建次数与关闭重验，保留所有原始 JSONL。
跨进程 inclusive/exclusive 累计仍不可替代 `comparison.json` 的墙钟。
失败、超时、样本少于原计划、缺失 audit、关闭重验异常时停止解释加速比并排查原始日志。

### 5. 较大布局负载及真实生产矩阵

smoke A/B 完整通过后，执行四视图 93 布局负载。可用 `--repeats 3` 交替 0/1 顺序、报告中位数；先用 1 确认环境与成本。

```bash
python3 experiment/run_joint_performance_comparison.py \
  --input "$REPO/experiment/inputs/l3-joint-redefined-four-views.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/ab-four-views" --repeats 1 \
  > "$CHECK_ROOT/ab-four-views.log" 2>&1
LARGE_AB_STATUS=$?
printf 'large_ab_status=%s\n' "$LARGE_AB_STATUS"
cat "$CHECK_ROOT/ab-four-views/comparison.json"
```

然后启用默认优化执行完整现有生产集合（4 + 6 + 8 + 12 项）；现有生产测试保留独立审计及原始事件篡改拒绝。

```bash
export RV2X86_JOINT_OPERATION_REUSE=1
unset RV2X86_VALIDATION_TIMING
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_definitions_production.py \
  pytools/tests/test_l3_multi_object_production.py \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_production.py \
  --basetemp="$CHECK_ROOT/production-pytest" \
  --junitxml="$CHECK_ROOT/production.xml" > "$CHECK_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 110 "$CHECK_ROOT/production.log"
```

要求 30 passed、没有非预期 skip/failure/error；实际数量以同一提交 collect 和 JUnit 为准。
不通过增大并行度掩盖串行瓶颈，不混用不同样本数或不同语义域计算加速比。
下一轮分析至少保存 `git-head.txt`、focused/production 的日志和 JUnit、两套 A/B 的 comparison.json、所有 timing JSONL/summary、失败时原始生产/audit 日志。
本轮真正的端到端加速结论须待主机上述结果，不能从本地 fixture 或计时 API 返回成功直接推出。

# Phase134：来源验证、依赖复查与 typed harness 性能修订

基线：Phase133 远端 `92fb91fe96088e4fc527ace329a74e4bb588a6d7`。
分支：`phase134-joint-provenance-performance`。

## 交付范围

本轮只优化已声明支持的 joint 翻译/评估路线，不扩大语义域、不减少调用或布局，不改变证明及比较条件。
Phase133 主机已完成 315 项快速回归、10+20 项生产矩阵、小负载及 93 布局 A/B；这些是本轮基线，不能替代本轮主机验收。
M2/M3 的单 asm 多效应、一般地址/值表达式和其它 fence 域等覆盖缺口仍未全部补齐。

### 1. 实际完整校验与依赖两轮复查

`joint_validation_operation` 增加只活在当前操作内的依赖 epoch：初检和关闭复查各有空的新结果表。
相同 joint/base 依赖在同一轮内共享成功结果；所有初检依赖在关闭轮都会再次核验，即使没有父节点再次请求它。
关闭轮绝不消费初检缓存。所有返回值仍深拷贝、JSON 原生、类型敏感比较。
嵌套 selection/capture session 可以把复查责任交给明确的外层 epoch；外层返回前失败则不能返回成功。
无外层操作、不同评估、独立审计、进程和线程不共享这些信任结果。逐成员文件、authority、receipt、原始输出、比较和结果身份检查仍保留。

新增 `joint.base-backend-full-validation` 是真正完整验证入口，包括 session 关闭调用；`joint.base-backend-request` 记录请求，不把命中算成完整检查。
新增 `joint.provenance-full-validation`、`joint.provenance-checkout-content`、`joint.provenance-repository-metadata` 和 `joint.provenance-git.*`，定位 Git 子命令开销。
旧的 `joint.base-backend-validation` 仍是 wrapper 阶段，不能把它当作完整校验的唯一统计来源。
所有阶段累计时间均可能嵌套、跨进程，不能相加代替墙钟。

### 2. 批量来源验证；不需要重新编译 QEMU

保留 `l3_qemu_backend.py`、`l3_qemu_dependencies.py` 和既有基础后端的固定文件原样。
新增 `l3_base_validation` / `l3_dependency_validation`，由新 joint wrapper 固定其实现摘要。
它们对同一个 v2 基础后端执行完整原有门槛。完整后端及配置门槛有 AST 等价测试；来源验证有真实仓库的快照一致性与拒绝测试。

仓库定位、Git 目录、提交和树身份用兼容旧 Git 的一次 rev-parse 查询取得；避免重复的根目录元数据查询。
不删除 Git status、fsck、gitlinks、依赖集合、独立 Git 目录、alternates、配置及命令记录检查。
每次完整验证仍读取所有跟踪文件的真实字节，核验 Git blob、SHA-256、权限、类型及符号链接；父目录检查保持逐文件执行。
没有依据 mtime/大小或索引状态省略内容检查，也没有跨验证保留元数据缓存。
真实本地六仓库 fixture 中，同一完整验证的 Git 调用从 56 次降至 29 次；这是结构性工作量结果，不是主机速度声明。
旧基础后端与已构建 QEMU 可以复用；新的 joint wrapper 必须重建，不能手改旧摘要。

### 3. 损坏证据先拒绝

`replay_group` 在后端/部署重建前先检查已绑定原始轨迹和命令记录的摘要。
已损坏或缺失的证据不能因此获批；只提前报告完整性失败。正常证据仍完成后续所有重建、轨迹解析、比较和审计。
此项可减少生产测试末尾故意删除事件后的负例耗时，不删除负例测试，也不把环境错误伪装为语义反例。

### 4. 保持精确对象大小的 table harness

多对象 harness 将逐样本重复 C 代码改为数据表驱动循环。
每次真实调用仍建立精确大小、正确类型、64 字节对齐的 typed VLA，按批准布局派生所有 view；没有扩大有效 backing object，也没有类型不明的字节缓冲区替代。
样本、初值、参数、别名分区、相对地址、实际调用、对象输出和返回值均保持原计划。
原生执行对照覆盖窄宽/signed 对象、fence、重载及 93 布局；新旧 L2 边界/最终输出严格一致，93 布局生成代码小于旧版一半。
L3 原函数仍在独立 TU 中构建，现有原函数机器码不变检查继续保留。

L2 observation 和 deployment 新写入 v2，并绑定明确 `harnessGenerator`；v1 回放按原 expanded 算法处理。
回放消费记录中的已注册生成方式，不依据当前环境开关猜测。未知生成方式拒绝。
因此用默认优化模式仍可审计本轮生成的基线模式记录。不能把 Phase133 的旧后端/结果直接换摘要后用于新实现。

### 5. 联合 producer 输入批量闭合

只有完整、编译器确认的 joint 报告采用批量 compiler binding；进入 producer 前和返回后各重新闭合一次，保留所有成员检查。
部分报告、其它路线仍按原来逐成员逻辑。已批准外部 producer 仍实际运行，保留超时、进程退出、stderr、请求/响应、工具与文件身份验证。
没有让子进程信任父进程的 verified 标记，也没有自动在当前进程执行任意外部 producer。
独立 producer 子进程的重复验证仍有成本，未声称本轮已消除所有跨进程开销。

## 开关与 A/B 含义

- `RV2X86_JOINT_OPERATION_REUSE=1`：保留 Phase133 操作内复用；独立审计仍新会话。
- `RV2X86_JOINT_PERFORMANCE_V2=1`：开启本轮来源验证、epoch 依赖共享、完整性预检、table harness、producer batch；默认开启。
- `RV2X86_JOINT_PERFORMANCE_V2=0`：同代码恢复 Phase133 算法路径，用于本轮增量对照；不是关闭审计。

`run_joint_performance_comparison.py --comparison-scope phase134` 默认在两个模式中都开启 Phase133 复用，只切换本轮 V2。
选择 `--comparison-scope phase133` 时，两端都关闭 V2，仅比较 Phase133 的复用开关，便于解释旧实验。
汇总 schema 升为 v2，目录改为 `repeat-0-mode-0/1`。每行列出 mode、operationReuse、performanceV2；墙钟字段为 baselineSeconds/optimizedSeconds/speedup。
不要再按旧目录名 `reuse-0/1` 或旧字段 fullWorkSeconds/reuseSeconds 读取本轮实验。

## 本地验证记录

扩大 joint、旧基础后端、来源验证、L2/L3 ingress、evaluation、provider 和 batch 回归：**398 passed、4 skipped**（缺少真实 Clang 的 AST 检查）。
覆盖账本、调用边界及生产测试收集：**32 passed、30 skipped**（30 项需要真实校准双 ISA 后端）。
关闭本轮 V2 的旧算法对照回归：**130 passed**。这些范围有重叠，不合并计数。
本地原生/Git fixture 不等于真实 QEMU/RISC-V 生产批准；本轮端到端加速比和生产矩阵必须由主机取得。

## 主机功能与性能验收

逐块执行；非预期失败先保留日志排查，不启动后续长矩阵。均不使用 exit，不清理旧结果。
保持现有 .venv-l2。Python/C++ 目标翻译语义没有改变，沿用已验收前端即可。

### A. 环境与快速回归

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase134-joint-provenance-performance
git switch --track origin/phase134-joint-provenance-performance
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
case "$PATH" in /usr/lib/llvm-10/bin:*) ;; *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;; esac
hash -r
export RV2X86_JOINT_OPERATION_REUSE=1
export RV2X86_JOINT_PERFORMANCE_V2=1
unset RV2X86_VALIDATION_TIMING
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase134-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
python3 -m pytest -q -rs \
  pytools/tests/test_joint_provenance_performance.py \
  pytools/tests/test_joint_table_harness.py \
  pytools/tests/test_joint_operation_replay.py \
  pytools/tests/test_joint_performance_comparison.py \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_l3_qemu_dependencies.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_evaluation_runner.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

如分支已存在，使用 git switch 后 git merge --ff-only 对应 origin 分支，不恢复本地 build 修改。
预期无失败，真实 Git fixture、类型化 native 执行和篡改检查全部通过。这些测试本身不授予双 ISA 生产批准。

### B. 新建 joint wrapper，复用旧基础后端

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" > "$CHECK_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 60 "$CHECK_ROOT/joint-backend.log"
cat "$CHECK_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
```

要求 stage=complete、complete=true、12 项校准完成；semanticApproval=false 正常。
不要重新编译 QEMU，不改旧基础后端文件。准备失败时读取日志，不绕过固定摘要门槛。

### C. 小负载增量 A/B

```bash
python3 experiment/run_joint_performance_comparison.py \
  --comparison-scope phase134 \
  --input "$REPO/experiment/inputs/l3-joint-load-add-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/ab-small" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  > "$CHECK_ROOT/ab-small.log" 2>&1
AB_STATUS=$?
printf 'ab_status=%s\n' "$AB_STATUS"
cat "$CHECK_ROOT/ab-small/comparison.json"
```

两端 operationReuse=1；mode0 performanceV2=0，mode1 performanceV2=1。
每次均需生产 complete、全部 L0–L3 verified、独立审计通过及负载/输出对照一致。
预期 3 成员、每端 8 样本和 16 访存事件，complete=true、每行 accepted=true；汇总 semanticApproval=false 不代表失败。

### D. 93 布局增量 A/B

C 通过后执行，不要先重跑整个矩阵。

```bash
python3 experiment/run_joint_performance_comparison.py \
  --comparison-scope phase134 \
  --input "$REPO/experiment/inputs/l3-joint-redefined-four-views.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/ab-large" --repeats 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  > "$CHECK_ROOT/ab-large.log" 2>&1
LARGE_STATUS=$?
printf 'large_status=%s\n' "$LARGE_STATUS"
cat "$CHECK_ROOT/ab-large/comparison.json"
```

预期两端均 4 成员、每端 93 样本、372 个访存事件，均验收通过。
A/B 每次都生成新证据，不混用旧 ELF 或轨迹。不同 harness 的原始 ELF/地址可以不同；每次验收仍核对本次真实产物、机器区域和文件绑定。

```bash
for CASE in ab-small ab-large
do
  for MODE in 0 1
  do
    RUN_ROOT="$CHECK_ROOT/$CASE/repeat-0-mode-$MODE"
    for KIND in production audit
    do
      python3 experiment/inspect_validation_timing.py \
        --input "$RUN_ROOT/$KIND-timing.jsonl" \
        > "$RUN_ROOT/$KIND-timing-summary.json"
      TIMING_STATUS=$?
      printf 'case=%s mode=%s kind=%s timing_status=%s\n' "$CASE" "$MODE" "$KIND" "$TIMING_STATUS"
    done
  done
done
```

重点对比 base-backend-full-validation、provenance-git.*、provenance-checkout-content、l2-program-full-rebuild、operation-closing-replay。
mode0 保持旧 pinned 来源模块，因而没有 provenance-git.* 子阶段记录；这不表示它没有执行 Git 检查，两端实际完整校验可比较 base-backend-full-validation。
实际完整次数会包含 producer 子进程的独立检查；不能把 capture 子树必须有几次校准当作通过条件。
初检及关闭轮必须保留。损坏证据负例可能在进入昂贵阶段前拒绝，这不能外推为正常证据可以略过该阶段。

### E. 不依赖生成时开关的真实独立审计

用默认优化模式审计本轮 baseline 的 clean 结果，核验持久化 harnessGenerator：

```bash
RV2X86_JOINT_PERFORMANCE_V2=1 python3 experiment/inspect_joint_acceptance.py \
  --root "$CHECK_ROOT/ab-large/repeat-0-mode-0/production" \
  > "$CHECK_ROOT/cross-mode-audit.log" 2>&1
CROSS_STATUS=$?
printf 'cross_mode_audit_status=%s\n' "$CROSS_STATUS"
cat "$CHECK_ROOT/cross-mode-audit.log"
```

预期 verified、全部成员完成、programExecutionUnitCount=1、93 布局全部调度。

### F. 最终完整生产矩阵

```bash
export RV2X86_JOINT_PERFORMANCE_V2=1
export RV2X86_JOINT_OPERATION_REUSE=1
unset RV2X86_VALIDATION_TIMING
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_definitions_production.py \
  pytools/tests/test_l3_multi_object_production.py \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_production.py \
  --durations=30 \
  --basetemp="$CHECK_ROOT/production-pytest" \
  --junitxml="$CHECK_ROOT/production.xml" > "$CHECK_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 150 "$CHECK_ROOT/production.log"
```

预期 30 passed，无失败及非预期跳过。保留原来的重复独立审计与损坏轨迹拒绝测试；pytest 目录末尾含故意损坏的证据，不作为 clean 验收归档。
仅在最终整合后重跑一次完整矩阵。正式论文性能需另开输出目录 --repeats 3 或更多，同机同负载、不并行竞争，报告原始值/中位数/波动。
性能数据使用 comparison.json 墙钟，不使用 cProfile 时间或跨进程 inclusive 累加；不要预设必须达到某个加速比来改变功能结论。

## 仍保留的性能成本

外部 producer 的进程/超时/信任边界仍在；未引入跨进程持久化信任缓存。
每个独立评估/审计都有自己的来源初检和关闭复查；完整源码与 Git 对象检查仍会耗时。
未删除正式正例/负例审计，也未以并行度掩盖串行验证成本。
本轮降低的是重复工作及生成/编译成本，不声称穷尽所有性能问题。实际收益待上述真实主机 A/B 与矩阵确认。

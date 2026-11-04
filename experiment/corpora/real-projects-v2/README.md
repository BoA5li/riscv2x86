# 真实项目语料 v2：完整发布包普查与保守待测池

基于 Phase144 的 v1 扩展，v1 原始文件与账本保持不变。本版固定 GMP 6.3.0、
musl 1.2.5、Linux 6.6 的同一批 SHA256 发布包，取消 v1 的头文件目录限制和
基于 `__riscv` 关键词的分支筛选。

## 本版收集标准

1. 枚举完整发布包的全部非目录条目，普通文件记录路径、字节数和 SHA256；
   链接等非普通条目单独记录，不能当作已完成构建上下文。
2. 考虑整个项目的 C/C++、头文件、`.inc`、`.c.in/.h.in`、`.C/.H`、`.c++/.h++`、
   `.ipp/.tcc/.def` 和 shipped 源码，不限 `arch/riscv` 目录。其他生成器、构建
   文件以及含 C asm 调用形状的其他文本，进入生成/模板待核查记录。
3. 所有源码中发现的 GNU asm 语法位置均保留，不按架构、指令类型、浮点/特权、
   翻译器是否支持或预期能否通过删减。条件分支不求值：`!defined(__riscv)`、
   `else`、`#if 0` 等都保留待原始构建确认。
4. 原始字节与编译器接口不变。寄存器声明、符号别名、basic/file asm、extended
   asm 和未解析 token 均只是语法候选；不能混作可运行的函数内汇编成功样本。
5. 建立 asm 宏提供者及传递别名的保守图，再扫描整个 C 源码范围，记录调用方
   的文本引用。调用者不要求含字面 asm 关键字。重名宏、注释及未激活分支会
   引入过近似引用，这是保留线索，不是编译器已确认的宏展开。
6. token 拼接、生成器及词法扫描异常进入 review-required，不能被解释为“没有
   汇编”或默默丢弃。未保存在小型快照中的调用方/拼接文件可通过固定完整发布包
   重现，其文件身份均在发布包账本中。
7. 架构提示只用于查看分组。`riscv-path`、`riscv-reference-needs-cpp`、
   `shared-or-undetermined`、`other-architecture-path-retained` 都没有删除权限。

这是一份覆盖真实 RISC-V 待测来源的**保守超集**：不把其它架构原语当作 RISC-V
有效样本，也不通过推测架构条件提前删掉可能适用的共享源码。

## 数据层次

每个项目独立存储 manifest 和二进制分片。分片不改变源内容；工具按清单拼接、
验证摘要并展开。逻辑资产包括：

| 资产 | 用途 |
|---|---|
| `release-files.jsonl.gz` | 整个发布包文件账本，包含未入小型快照的文件 |
| `sources.tar.gz` | 原始 asm 线索文件、相关生成模板、许可证；内容不改写 |
| `sites.jsonl.gz` | asm 源位置、原字节、范围及身份，全部未授予适用性 |
| `macro-providers.jsonl.gz` | asm 提供者/传递别名和 token-paste 宏定义线索 |
| `macro-references.jsonl.gz` | 完整 C 范围内宏名引用的保守文件索引 |
| `review-required.jsonl.gz` | 拼接、生成器与扫描异常等待核查记录 |
| `index.tsv.gz` | 人可读语法位置索引 |

完整原始工程是 sources.lock.json 锁定的发布包；小型快照不冒充完整工程。
全工程调用图、ABI、全部编译配置、运行环境及宏展开闭包都不是词法清点能证明的。
所有条目保持 activationStatus=not_checked、eligibilityStatus=not_assessed、
translationStatus/validationStatus=not_run，semanticApproval 和
productionAcceptanceComplete 为 false。

## 明确补入的遗漏

- musl 的 `src/math/riscv64/` 浮点原语，不因当前翻译器不支持而删除。
- musl 公共源码中的编译器屏障、启动/动态链接代码、宏提供者与共享上下文。
- Linux 的 kernel、mm、kvm、UAPI、公共 include、工具与自测等范围，不再只看
  RISC-V asm 头文件；域外、复杂环境和未激活情况之后依配置如实归类。
- GMP 全 C/C++ 及头文件范围，包括共享和其他架构条件中的 asm，并保留构建
  配置判断依据，而不假定只有 longlong.h 中的一个语句才值得清点。

其它架构和架构中立代码、文档/生成模板线索均不作为 RISC-V 成功率分母。必须
由原始构建与编译器事实核定域内集合，不能根据翻译失败再反向筛选。

## 固定发布包的实际清点结果

| 项目 | 发布包普通文件 | C/C++/头文件及模板 | asm 语法候选位置 | 原始快照文件 | 宏引用候选文件 | 待核查记录 |
|---|---:|---:|---:|---:|---:|---:|
| GMP 6.3.0 | 2,156 | 1,045 | 264 | 60 | 301 | 26 |
| musl 1.2.5 | 2,697 | 2,336 | 1,070 | 271 | 50 | 14 |
| Linux 6.6 | 81,703 | 56,948 | 12,523 | 1,906 | 50,811 | 3,937 |

Linux 另有 63 个非普通文件条目，均在完整账本中。语法候选总计 13,857，包含
寄存器绑定、文件级 asm、符号别名、其它架构及未知 token，**不是 13,857 个
RISC-V 内联汇编测试**。宏索引跨条件、跨文件合并同名定义，会形成很宽的保守
超集；不能将宏引用文件数作为实际宏实例数或覆盖率分母。

`v1-migration.json` 对照原版全部 316 个语法位置的路径、原文件摘要与字节区间，
缺失数为 0；其中原版 selected 项为 139（包含寄存器绑定）。原版统计没有被
新统计覆盖或改写。asm 紧接注释的扫描边界还补入了 Linux
`tools/testing/radix-tree/Makefile` 生成线索，仍保留为待核查，不计为已确认内联
汇编实例。新增源码包括 12 个 musl RISC-V 浮点实现以及 Linux RISC-V
kernel/mm/kvm 中原先遗漏的 C 源位置。

## 本地更新和源级核验

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase145-whole-project-corpus
if git show-ref --verify --quiet refs/heads/phase145-whole-project-corpus; then
  git switch phase145-whole-project-corpus
  git merge --ff-only origin/phase145-whole-project-corpus
else
  git switch --track origin/phase145-whole-project-corpus
fi
export REPO="$PWD"
export CORPUS_WORK="$(mktemp -d "$REPO/experiment/results/real-corpus-v2-XXXXXX")"
git rev-parse HEAD > "$CORPUS_WORK/git-head.txt"
printf 'CORPUS_WORK=%s\n' "$CORPUS_WORK"
python3 experiment/whole_project_corpus.py verify \
  > "$CORPUS_WORK/inventory-audit.json" 2>&1
VERIFY_STATUS=$?
printf 'whole_corpus_verify_status=%s\n' "$VERIFY_STATUS"
cat "$CORPUS_WORK/inventory-audit.json"
```

要求退出码 0、status=verified-whole-release-census。未经完整发布包重放时
upstreamReplayComplete=false 正常；编译激活/语义批准字段为 false 也是正确边界。
该验证状态不授予翻译通过或所有构建实例已收齐的结论。

```bash
python3 experiment/whole_project_corpus.py materialize \
  --output "$CORPUS_WORK/materialized" \
  > "$CORPUS_WORK/materialize.json" 2>&1
MATERIALIZE_STATUS=$?
printf 'materialize_status=%s\n' "$MATERIALIZE_STATUS"
```

每个项目有 `upstream/` 原始线索源码和展开的 JSONL/TSV 账本。不要把头文件、
未激活分支或其它架构文件直接当作独立 C 程序批量运行，也不应手改汇编适配测试。

## 下载完整原始工程，独立复现全部收集过程

```bash
python3 experiment/whole_project_corpus.py download \
  --output "$CORPUS_WORK/archives" \
  > "$CORPUS_WORK/download.json" 2>&1
DOWNLOAD_STATUS=$?
printf 'download_status=%s\n' "$DOWNLOAD_STATUS"
```

仅在下载状态为 0 后继续；也可以使用原有经过 SHA256 核验的完整发布包目录。
该命令不重新构建编译器/QEMU，也不执行上游项目构建脚本。

```bash
python3 experiment/whole_project_corpus.py verify \
  --archives "$CORPUS_WORK/archives" \
  > "$CORPUS_WORK/upstream-replay.json" 2>&1
REPLAY_STATUS=$?
printf 'upstream_replay_status=%s\n' "$REPLAY_STATUS"
python3 experiment/whole_project_corpus.py materialize \
  --archives "$CORPUS_WORK/archives" \
  --output "$CORPUS_WORK/full-context" \
  > "$CORPUS_WORK/full-context.json" 2>&1
CONTEXT_STATUS=$?
printf 'full_context_status=%s\n' "$CONTEXT_STATUS"
```

上游重放应返回 upstreamReplayComplete=true。全库普查会重新读取发布包并建立
宏引用线索，耗时明显长于本地分片摘要检查。full-context 中 `full-release/` 保留
完整发布包的普通文件；工具不会创建文件系统链接，链接身份保留在文件账本中。
实际构建若依赖这些链接，须在独立目录使用已核验的原始发布包按上游方法展开和
构建，不能声称普通文件视图已具备所有构建前提。

重建新的语料副本以复现：

```bash
python3 experiment/whole_project_corpus.py build \
  --archives "$CORPUS_WORK/archives" \
  --output "$CORPUS_WORK/rebuilt-corpus" \
  > "$CORPUS_WORK/rebuild.log" 2>&1
BUILD_STATUS=$?
printf 'corpus_rebuild_status=%s\n' "$BUILD_STATUS"
python3 -m pytest -q -rs \
  pytools/tests/test_real_project_corpus.py \
  pytools/tests/test_whole_project_corpus.py \
  --junitxml="$CORPUS_WORK/collector-tests.xml" \
  > "$CORPUS_WORK/collector-tests.log" 2>&1
TEST_STATUS=$?
printf 'collector_tests_status=%s\n' "$TEST_STATUS"
cat "$CORPUS_WORK/collector-tests.log"
```

## 本轮回归

采集工具与原版工具共 44 项测试通过，覆盖否定架构条件、条件分支、四种 asm
拼写、asm 紧接注释、宏别名、形式参数、注释/字符串、拼接及生成器、原始字节区间、分片损坏、
发布包摘要错误、重建确定性、拒绝未授予的通过标签，以及已发布数据对 v1 和
已知遗漏源码的保留。测试通过仅说明收集/归档逻辑，不授予 L0–L3 通过。

`collection-validation.json` 保存本轮回归、展开、v1 位置保留和完整上游发布包
重放结果，并绑定采集器摘要及 catalogIdentity。完整发布包已按当前规则重新
收集并比对通过；这不代表编译激活或翻译评估已完成。

## 下一阶段的完成条件

本版解决“先把所有可能相关的原始数据收进可追溯待测池”，没有把词法选择提升为
编译器判断。后续应在固定 RV64GC/LP64D 上游构建配置下记录预处理、依赖、AST、
宏展开映射、所在原函数和生成文件。所有未知项都保留 disposition；实现不支持
的语义记作覆盖缺口，不能为了结果通过而删改原始代码或移出已声明域。

只有完成这些检查，才能确定该配置下实际 RISC-V 内联汇编测试分母。全配置下的
动态生成与宏实例完备性不能仅凭本版源级清点宣称完成。

## 来源与许可

版本、上游 URL、实际获取镜像和发布包 SHA256 继承 v1，原始字节不改写。
musl 发布包由 Alpine 镜像取得，匹配 Buildroot 记录和镜像；GMP/Linux 来自
官方站点，Linux SHA256 与官方清单一致。未独立验证 OpenPGP 签名，相关字段
保留 false。快照保留原始版权及许可证，不将第三方源码重新许可为翻译器代码。
本轮未修改翻译器或 L0–L3 评估模块。

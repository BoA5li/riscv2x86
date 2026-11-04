# 真实项目源语料 v1（Phase144）

翻译器基线：`cde2f6e3f36ff78f86ec99364fc8b53d3cc7cb42`。
本目录冻结 **真实原始源码子集与完整词法候选账本**，不根据翻译成功与否选取样本。
它还不是“已确认所有条目符合 RV64GC 构建条件”的可执行测试集。
这些是预先冻结的发布版本，不代表项目最新版本，也没有根据翻译通过率挑选版本。
扩展新版本需要保留独立版本身份和新的构建记录。

## 来源、固定范围和实际规模

| 来源 | 固定版本 | 原始源码扫描范围 | 范围内头文件 | asm 语句候选 | 固定寄存器声明候选 |
|---|---|---|---:|---:|---:|
| GNU GMP | 6.3.0 | `longlong.h`，候选范围为出现 `__riscv*` 的条件分支 | 1 | 1 | 0 |
| musl | 1.2.5 | `arch/riscv64/**/*.h`，包含直接子文件 | 15 | 7 | 29 |
| Linux | v6.6 | `arch/riscv/include/asm/**/*.h`，包含直接子文件 | 129 | 88 | 14 |
| 合计 | 固定版本，不随 master 漂移 | 原始源码按来源分类 | 145 | 96 | 43 |

“asm 语句候选”包括 basic asm、文件级汇编与宏定义内的 asm，不能都称作函数内
extended inline asm，也不代表都适用于当前翻译器。词法候选不等于动态执行次数、
唯一指令模板、独立函数、预处理激活实例或实验通过数。固定寄存器声明单独列出，
不充当可执行 asm 成功样本。

GMP 原始头文件还包含 177 个其他架构的语法位置，均保留在账本并明确标记
`other_architecture_branch`；不计入 RISC-V 候选分母。该范围的 RISC-V 候选是原始
`umul_ppmm` 宏中的 `mulhu`，没有为凑规模重复实例化。

musl 的 7 个 asm 候选包括屏障、32/64 位 CAS、启动文件级 asm、线程指针读取、
控制转移和系统调用宏。Linux 的 88 个包括 81 个带操作数分隔符的扩展候选和
7 个 basic/宏候选。未按指令族或翻译器是否支持进行删减，CSR、向量、系统操作
和复杂接口均保留。条件是否在实际构建中激活，必须由下一阶段编译器记录确认。

本轮没有覆盖 GMP 的独立汇编文件、musl 的 `.s`，也没有声称扫描整个 Linux：
Linux 的 `arch/riscv/kernel/*.c`、UAPI、其他目录和项目外依赖不在本轮固定范围。
若扩展范围，建立新版本语料，不能悄悄改变本版分母。

## 目录内容

```text
sources.lock.json           官方版本、URL、发布包 SHA256、范围、取得来源
catalog.json                三个项目的身份和计数
README.md                  方法和适用边界
{gmp,musl,linux}/
  sources.tar.gz           原始范围文件、必要支持文件、原始许可证
  manifest.json            每个文件的身份、角色、字节数及数据资产身份
  sites.jsonl.gz           每个语法位置的完整账本
  index.tsv                便于阅读的位置和状态索引
```

原始文件内容逐字节保留；压缩包的时间、uid/gid、模式等容器元数据规范化。
`sites.jsonl.gz` 保留原始文件相对路径、SHA256、起止字节、原始行号、片段 SHA256、
Base64 原字节、条件上下文与语法类别。注释、字符串和 `#include <asm/...>` 中的
单词不会被算作汇编位置；续行保持到原始文件的字节映射。无法闭合的 asm token
若出现将作为 unresolved 保留，扫描错误不静默跳过。

词法条件识别不替代预处理，宏定义中的一个位置也不等于所有宏展开实例。
所有条目的 activationStatus=not_checked、eligibilityStatus=not_assessed、
translationStatus=not_run、validationStatus=not_run。清点成功不授予语义批准。

## 官方来源与镜像说明

- GMP：<https://gmplib.org/>，6.3.0 官方包；内联汇编组织说明：
  <https://gmplib.org/manual/Assembly-Coding>。
- musl：<https://git.musl-libc.org/cgit/musl/>，1.2.5 官方发布版本。
  本次官方发布服务器返回 503，使用 Alpine 的原始发布包镜像，并与 Buildroot
  镜像交叉比较：两个包字节相同，SHA256 都是
  `a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4`。
  对照 Buildroot 官方历史发布记录：
  <https://lists.buildroot.org/pipermail/buildroot/2024-March/372259.html>。
  没有使用第三方修改后的 musl 源码树。
- Linux：<https://www.kernel.org/>，6.6 官方发布包；已与官方
  <https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc> 对应条目比较。

本轮未独立验证发布包的 OpenPGP 签名，lock 明确保留 signatureVerified=false；
不能把 SHA256 比较描述成已完成签名验证。全部发布包的实际 SHA256 见 lock。

## 许可与出处保留

每个 sources.tar.gz 内含上游原始版权/许可文本。GMP 保留 COPYING、
COPYING.LESSERv3、COPYINGv2、COPYINGv3；musl 保留 COPYRIGHT；Linux 保留 COPYING
及发布包内完整 LICENSES 目录和各文件 SPDX/版权标识。这些源码保留各自上游
许可证，不因纳入翻译器仓库而被重新许可。musl 另保留 `src/internal/atomic.h`
作为支持源码；它不进入本轮架构头文件候选扫描分母。

## 本地更新和核验

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase144-real-project-corpus
if git show-ref --verify --quiet refs/heads/phase144-real-project-corpus; then
  git switch phase144-real-project-corpus
  git merge --ff-only origin/phase144-real-project-corpus
else
  git switch --track origin/phase144-real-project-corpus
fi
export REPO="$PWD"
export CORPUS_ROOT="$REPO/experiment/corpora/real-projects-v1"
export CORPUS_WORK="$(mktemp -d "$REPO/experiment/results/real-corpus-XXXXXX")"
git rev-parse HEAD > "$CORPUS_WORK/git-head.txt"
printf 'CORPUS_WORK=%s\n' "$CORPUS_WORK"
python3 experiment/real_project_corpus.py verify \
  > "$CORPUS_WORK/inventory-audit.json" 2>&1
VERIFY_STATUS=$?
printf 'corpus_verify_status=%s\n' "$VERIFY_STATUS"
cat "$CORPUS_WORK/inventory-audit.json"
```

要求退出码 0、status=verified-source-inventory。该状态只表示冻结的源码资产和
重新生成的词法账本一致，不表示编译激活或翻译通过。

将压缩数据展开为按项目分类的可阅读源码（新目录，不覆盖已有数据）：

```bash
python3 experiment/real_project_corpus.py materialize \
  --output "$CORPUS_WORK/materialized" \
  > "$CORPUS_WORK/materialize.json" 2>&1
MATERIALIZE_STATUS=$?
printf 'materialize_status=%s\n' "$MATERIALIZE_STATUS"
```

展开后每个项目有 upstream/ 原始文件、sites.jsonl 与 index.tsv。**这些头文件
不能直接作为 automatic_batch_cli 的独立 C 程序输入。** 不会把切下的语句伪装为
官方完整测试函数。本轮没有人工生成缩小参数、删除控制流或修补约束的成功样本。

如需独立重做官方归属和固定范围完整性核验，下载完整发布包并重放：

```bash
python3 experiment/real_project_corpus.py download \
  --output "$CORPUS_WORK/archives" \
  > "$CORPUS_WORK/download.json" 2>&1
DOWNLOAD_STATUS=$?
printf 'download_status=%s\n' "$DOWNLOAD_STATUS"
```

仅当 download_status=0 时继续（Linux 完整发布包约 140 MB）。工具验证全部 SHA256，
官方 musl URL 不可用时才尝试 lock 中明确登记的原始发布包镜像。

```bash
python3 experiment/real_project_corpus.py verify \
  --archives "$CORPUS_WORK/archives" \
  > "$CORPUS_WORK/upstream-replay.json" 2>&1
UPSTREAM_STATUS=$?
printf 'upstream_replay_status=%s\n' "$UPSTREAM_STATUS"
cat "$CORPUS_WORK/upstream-replay.json"
python3 experiment/real_project_corpus.py build \
  --archives "$CORPUS_WORK/archives" \
  --output "$CORPUS_WORK/rebuilt-corpus" \
  > "$CORPUS_WORK/rebuild.json" 2>&1
REBUILD_STATUS=$?
printf 'rebuild_status=%s\n' "$REBUILD_STATUS"
```

要求上游重放退出码 0、upstreamArchiveReplayComplete=true；工具从完整发布包重新
枚举固定范围，核对快照中每一个文件和每个候选，而非只相信现有清单标签。
重建目录属于独立复现产物，不修改本仓库冻结语料。

工具本身的正反例回归（原始片段字节、条件、注释/字符串、续行、固定寄存器、
坏 hash、篡改账本、路径逃逸、符号链接、重复输出等）：

```bash
python3 -m pytest -q -rs pytools/tests/test_real_project_corpus.py \
  --junitxml="$CORPUS_WORK/collector-tests.xml" \
  > "$CORPUS_WORK/collector-tests.log" 2>&1
COLLECTOR_STATUS=$?
printf 'collector_tests_status=%s\n' "$COLLECTOR_STATUS"
cat "$CORPUS_WORK/collector-tests.log"
```

## 下一阶段：从真实源语料到实际实验单元

1. 在完整上游源码树中，用固定 RV64GC/LP64D 配置和真实构建命令获取预处理输出、
   依赖及编译器 AST，将 header/macro 定义位置与展开位置建立对应关系。
2. 标明实际激活/未激活分支、文件级汇编、寄存器声明与函数内 asm，列出编译器
   或环境无法处理的条目。不得把未激活、未构建、未运行当作成功。
3. 以保留原始函数和接口的单元为主要实验单位。测试驱动可以新增，原始 asm、
   clobber、重要 C 外壳、活跃输出和原子/同步语义不得为了适配而删改。
4. 真实原程序与翻译程序分别完成有依据的 L0/L1/L2/L3 检查，按实际义务报告。
   不为无 L3 义务的程序制造 L3 成功，也不把受控环境结果改称原生系统调用等价。
5. 固定范围所有候选都保留 disposition。根据预先声明的前提核定域内集合，域内
   阻塞计作实现缺口；不能观察失败后才删除样本或重新定义支持域。
6. 按项目、唯一模板、展开实例、原函数和程序分别统计。当前 96 个语法候选
   不是 96 个独立可运行测试，也没有任何已证明的翻译通过率。

如要保留完整项目上下文构建，需要使用 SHA256 固定的完整发布包；本快照明确
不是整个项目的可编译源码树，不通过补写平台头文件掩盖缺失依赖。

## 发布前验证记录

- 从 SHA256 固定的三个完整发布包重新枚举范围，全部原始文件、角色和候选账本
  重放一致；记录见 release-verification.json。该记录不替代使用者的重新核验。
- 采集、完整性、真实快照片段溯源及拒绝篡改回归：25 passed。
- 展开三个项目成功；测试用例内验证了同环境下确定性重建和逐字节保持。
- 工具及测试通过 Python 3.10 语法解析，五个 Bash 命令块通过 bash -n。
- 编译激活、原始函数调用闭包、翻译与 L0–L3 评估均尚未执行，不计任何成功率。
